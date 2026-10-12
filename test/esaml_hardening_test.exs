defmodule EsamlHardeningTest do
  @moduledoc """
  Exercises the hardening applied to the vendored esaml modules by signing real
  SAML responses with the test key and running them through the same decode and
  validate path `Samly.SPHandler` uses.
  """
  use ExUnit.Case, async: false

  require Samly.Esaml
  require Record
  alias Samly.Esaml

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  @deflate "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE"
  @recipient "https://sp.example.com/sso/sp/consume/idp"
  @audience "urn:test:sp"
  @saml_ns [
    {~c"samlp", ~c"urn:oasis:names:tc:SAML:2.0:protocol"},
    {~c"saml", ~c"urn:oasis:names:tc:SAML:2.0:assertion"}
  ]

  setup_all do
    :esaml_util.start_ets()
    key = :esaml_util.load_private_key(~c"test/data/test.pem")
    cert = :esaml_util.load_certificate(~c"test/data/test.crt")
    {:ok, key: key, cert: cert, sp: sp(cert, key)}
  end

  describe "signed response validation" do
    test "accepts a freshly signed RSA-SHA256 response and rejects its replay", ctx do
      payload = signed_response(ctx)

      assert {:ok, assertion} = validate(payload, ctx.sp)
      assert Esaml.esaml_assertion(assertion, :recipient) == String.to_charlist(@recipient)

      assert {:error, :duplicate} = validate(payload, ctx.sp)
    end

    # The fixture is esaml's own valid RSA-SHA1 sample; signing one at test time
    # is impossible on hosts whose crypto policy forbids SHA-1 signatures.
    test "rejects RSA-SHA1 signatures as insecure" do
      {doc, _} =
        "test/data/signed_rsa_sha1.xml"
        |> File.read!()
        |> String.to_charlist()
        |> :xmerl_scan.string(namespace_conformant: true)

      assert {:error, :insecure_algorithm} = :xmerl_dsig.verify(doc, :any)
    end

    test "rejects content changed after signing", ctx do
      payload =
        ctx
        |> signed_response_xml()
        |> String.replace("user@example.com", "evil@example.com")
        |> Base.encode64()

      assert {:error, {:envelope, :bad_digest}} = validate(payload, ctx.sp)
    end

    test "rejects a signature whose reference points at another element", ctx do
      resp_id = "_resp_" <> random_id()

      payload =
        ctx
        |> signed_response_xml(resp_id: resp_id)
        |> String.replace(~s(ID="#{resp_id}"), ~s(ID="_someone_else"))
        |> Base.encode64()

      assert {:error, {:envelope, :bad_reference}} = validate(payload, ctx.sp)
    end

    test "rejects an assertion whose NotBefore is in the future", ctx do
      payload = signed_response(ctx, not_before: DateTime.add(DateTime.utc_now(), 3600))

      assert {:error, :assertion_not_yet_valid} = validate(payload, ctx.sp)
    end

    test "tolerates a NotBefore within the allowed clock skew", ctx do
      payload = signed_response(ctx, not_before: DateTime.add(DateTime.utc_now(), 60))

      assert {:ok, _assertion} = validate(payload, ctx.sp)
    end
  end

  describe "replay detection" do
    test "keys on the signed assertion, not the unsigned envelope", ctx do
      sp = assertion_only_sp(ctx.cert, ctx.key)
      resp_id = "_resp_" <> random_id()
      xml = signed_assertion_response_xml(ctx, resp_id: resp_id)

      assert {:ok, assertion} = validate_xml(xml, sp)
      assert Esaml.esaml_assertion(assertion, :recipient) == String.to_charlist(@recipient)

      # The envelope is unsigned, so an attacker can change it. The signed
      # assertion is untouched, so this must still be detected as a replay.
      replayed = String.replace(xml, ~s(ID="#{resp_id}"), ~s(ID="_replayed_#{resp_id}"))
      assert {:error, :duplicate} = validate_xml(replayed, sp)
    end

    test "does not flag a distinct assertion as a replay", ctx do
      sp = assertion_only_sp(ctx.cert, ctx.key)

      assert {:ok, _} = validate_xml(signed_assertion_response_xml(ctx), sp)
      assert {:ok, _} = validate_xml(signed_assertion_response_xml(ctx), sp)
    end
  end

  describe "untrusted XML parsing" do
    test "does not expand external entities", ctx do
      xxe =
        ~s(<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>) <>
          ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0">) <>
          ~s(<samlp:Status><samlp:StatusCode Value="&xxe;"/></samlp:Status></samlp:Response>)

      result = Samly.Helper.decode_idp_auth_resp(ctx.sp, nil, Base.encode64(xxe))

      assert {:error, reason} = result
      refute inspect(reason) =~ ~r/hostname contents never appear/
      refute inspect(reason) |> String.contains?(File.read!("/etc/hostname") |> String.trim())
    end

    test "turns malformed XML into an error instead of exiting", ctx do
      assert {:error, {:invalid_response, _}} =
               Samly.Helper.decode_idp_auth_resp(ctx.sp, nil, Base.encode64("<unclosed>"))
    end
  end

  describe "DEFLATE payloads" do
    test "inflates ordinary deflated messages" do
      xml = ~s(<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>)
      payload = Base.encode64(:zlib.zip(xml))

      assert {:xmlElement, :"samlp:Response", _, _, _, _, _, _, _, _, _, _} =
               :esaml_binding.decode_response(@deflate, payload)
    end

    test "refuses decompression bombs" do
      bomb = Base.encode64(:zlib.zip(:binary.copy(<<"A">>, 2 * 1024 * 1024)))

      assert catch_error(:esaml_binding.decode_response(@deflate, bomb)) ==
               :inflated_payload_too_large
    end
  end

  describe "Samly.Helper.request_id/1" do
    test "returns the ID of a generated AuthnRequest", ctx do
      req = :esaml_sp.generate_authn_request(~c"https://idp.example.com/sso", ctx.sp, :undefined)

      id = Samly.Helper.request_id(req)
      assert is_binary(id)
      assert String.starts_with?(id, "id")
    end
  end

  # -- helpers ---------------------------------------------------------------

  defp sp(cert, key) do
    Esaml.esaml_sp(
      key: key,
      certificate: cert,
      idp_signs_envelopes: true,
      idp_signs_assertions: false,
      trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}],
      metadata_uri: ~c"https://sp.example.com/sso/sp/metadata/idp",
      consume_uri: String.to_charlist(@recipient),
      entity_id: String.to_charlist(@audience)
    )
  end

  defp assertion_only_sp(cert, key) do
    Esaml.esaml_sp(
      key: key,
      certificate: cert,
      idp_signs_envelopes: false,
      idp_signs_assertions: true,
      trusted_fingerprints: [{:sha256, :crypto.hash(:sha256, cert)}],
      metadata_uri: ~c"https://sp.example.com/sso/sp/metadata/idp",
      consume_uri: String.to_charlist(@recipient),
      entity_id: String.to_charlist(@audience)
    )
  end

  defp validate(payload, sp) do
    xml = :esaml_binding.decode_response(:undefined, payload)
    :esaml_sp.validate_assertion(xml, &:esaml_util.check_dupe_ets/2, sp)
  end

  defp validate_xml(xml, sp) do
    payload = Base.encode64(xml)
    decoded = :esaml_binding.decode_response(:undefined, payload)
    :esaml_sp.validate_assertion(decoded, &:esaml_util.check_dupe_ets/2, sp)
  end

  defp signed_response(ctx, opts \\ []) do
    ctx |> signed_response_xml(opts) |> Base.encode64()
  end

  # Signs the Assertion element (leaving the envelope unsigned) and exports the
  # whole response to a string.
  defp signed_assertion_response_xml(ctx, opts \\ []) do
    {doc, _} =
      opts
      |> response_xml()
      |> String.to_charlist()
      |> :xmerl_scan.string(namespace_conformant: true)

    [assertion] =
      :xmerl_xpath.string(~c"/samlp:Response/saml:Assertion", doc, namespace: @saml_ns)

    signed =
      :xmerl_dsig.sign(assertion, ctx.key, ctx.cert, Keyword.get(opts, :sig_alg, :rsa_sha256))

    [replace_assertion(doc, signed)]
    |> :xmerl.export(:xmerl_xml)
    |> List.flatten()
    |> List.to_string()
  end

  # Replaces the (unsigned) Assertion element in a parsed response with a signed
  # copy, preserving the rest of the tree.
  defp replace_assertion(node, signed) do
    content =
      node
      |> xmlElement(:content)
      |> Enum.map(fn
        child when is_tuple(child) and elem(child, 0) == :xmlElement ->
          if xmlElement(child, :name) == :"saml:Assertion" do
            signed
          else
            replace_assertion(child, signed)
          end

        other ->
          other
      end)

    xmlElement(node, content: content)
  end

  # Signs the Response envelope with the test key and exports it to a string,
  # so the verification side re-parses it exactly as it would a real IdP POST.
  defp signed_response_xml(ctx, opts \\ []) do
    {doc, _} =
      opts
      |> response_xml()
      |> String.to_charlist()
      |> :xmerl_scan.string(namespace_conformant: true)

    signed = :xmerl_dsig.sign(doc, ctx.key, ctx.cert, Keyword.get(opts, :sig_alg, :rsa_sha256))

    [signed]
    |> :xmerl.export(:xmerl_xml)
    |> List.flatten()
    |> List.to_string()
  end

  defp response_xml(opts) do
    now = DateTime.utc_now()
    not_before = Keyword.get(opts, :not_before, DateTime.add(now, -60))
    not_after = Keyword.get(opts, :not_on_or_after, DateTime.add(now, 300))
    resp_id = Keyword.get(opts, :resp_id, "_resp_" <> random_id())

    """
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="#{resp_id}" Version="2.0" IssueInstant="#{fmt(now)}" Destination="#{@recipient}">
    <saml:Issuer>urn:test:idp</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion ID="_assertion_#{random_id()}" Version="2.0" IssueInstant="#{fmt(now)}">
    <saml:Issuer>urn:test:idp</saml:Issuer>
    <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
    <saml:SubjectConfirmationData NotOnOrAfter="#{fmt(not_after)}" Recipient="#{@recipient}" InResponseTo="id_request_1"/>
    </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="#{fmt(not_before)}" NotOnOrAfter="#{fmt(not_after)}">
    <saml:AudienceRestriction><saml:Audience>#{@audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
    <saml:Attribute Name="email"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
    </saml:Assertion>
    </samlp:Response>
    """
    |> String.replace("\n", "")
  end

  defp fmt(datetime), do: datetime |> DateTime.truncate(:second) |> DateTime.to_iso8601()

  defp random_id, do: 8 |> :crypto.strong_rand_bytes() |> Base.hex_encode32(case: :lower)
end
