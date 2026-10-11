defmodule Samly.Helper do
  @moduledoc false

  require Samly.Esaml
  alias Samly.{Assertion, Esaml, IdpData}

  @spec get_idp(binary) :: nil | IdpData.t()
  def get_idp(idp_id) do
    idps = Application.get_env(:samly, :identity_providers, %{})
    Map.get(idps, idp_id)
  end

  @spec get_metadata_uri(nil | binary, binary) :: nil | charlist
  def get_metadata_uri(nil, _idp_id), do: nil

  def get_metadata_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/metadata" |> String.to_charlist()
  end

  def get_metadata_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/metadata/#{idp_id}" |> String.to_charlist()
  end

  @spec get_consume_uri(nil | binary, binary) :: nil | charlist
  def get_consume_uri(nil, _idp_id), do: nil

  def get_consume_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/consume" |> String.to_charlist()
  end

  def get_consume_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/consume/#{idp_id}" |> String.to_charlist()
  end

  @spec get_logout_uri(nil | binary, binary) :: nil | charlist
  def get_logout_uri(nil, _idp_id), do: nil

  def get_logout_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/logout" |> String.to_charlist()
  end

  def get_logout_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/logout/#{idp_id}" |> String.to_charlist()
  end

  def sp_metadata(sp) do
    :xmerl.export([:esaml_sp.generate_metadata(sp)], :xmerl_xml)
  end

  def gen_idp_signin_req(sp, idp_metadata, nameid_format) do
    idp_signin_url = Esaml.esaml_idp_metadata(idp_metadata, :login_location)

    xml_frag = :esaml_sp.generate_authn_request(idp_signin_url, sp, nameid_format)

    {idp_signin_url, xml_frag}
  end

  def gen_idp_signout_req(sp, idp_metadata, subject_rec, session_index) do
    idp_signout_url = Esaml.esaml_idp_metadata(idp_metadata, :logout_location)
    xml_frag = :esaml_sp.generate_logout_request(idp_signout_url, session_index, subject_rec, sp)
    {idp_signout_url, xml_frag}
  end

  def gen_idp_signout_resp(sp, idp_metadata, signout_status) do
    idp_signout_url = Esaml.esaml_idp_metadata(idp_metadata, :logout_location)
    xml_frag = :esaml_sp.generate_logout_response(idp_signout_url, signout_status, sp)
    {idp_signout_url, xml_frag}
  end

  @doc """
  Decode and validate an IdP sign-in response, rejecting replays of a response already seen.

  Replay detection keys on the digest of the whole response and remembers it in
  ETS until the assertion would have expired anyway. The ETS tables are owned
  by the process `:esaml_util.start_ets/0` spawns from `Samly.Provider`, and
  the check is per-node (it is broadcast to connected nodes only).
  """
  def decode_idp_auth_resp(sp, saml_encoding, saml_response) do
    with(
      {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_response),
      {:ok, assertion_rec} <-
        :esaml_sp.validate_assertion(xml_frag, &:esaml_util.check_dupe_ets/2, sp)
    ) do
      {:ok, Assertion.from_rec(assertion_rec)}
    else
      {:error, reason} -> {:error, reason}
      error -> {:error, {:invalid_request, "#{inspect(error)}"}}
    end
  end

  @doc """
  Return the `ID` attribute of a generated SAML request element as a string.

  The ID is what the IdP echoes back as `InResponseTo`, so the SP-initiated
  flow stores it in the session to tie the response to the request it sent.
  """
  @spec request_id(tuple()) :: binary()
  def request_id(xml_elem) do
    {:xmlObj, :string, id} = :xmerl_xpath.string(~c"string(@ID)", xml_elem)
    List.to_string(id)
  end

  def decode_idp_signout_resp(sp, saml_encoding, saml_response) do
    resp_ns = [
      {~c"samlp", ~c"urn:oasis:names:tc:SAML:2.0:protocol"},
      {~c"saml", ~c"urn:oasis:names:tc:SAML:2.0:assertion"},
      {~c"ds", ~c"http://www.w3.org/2000/09/xmldsig#"}
    ]

    with {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_response),
         nodes when is_list(nodes) and length(nodes) == 1 <-
           :xmerl_xpath.string(~c"/samlp:LogoutResponse", xml_frag, [{:namespace, resp_ns}]) do
      :esaml_sp.validate_logout_response(xml_frag, sp)
    else
      _ -> {:error, :invalid_request}
    end
  end

  def decode_idp_signout_req(sp, saml_encoding, saml_request) do
    req_ns = [
      {~c"samlp", ~c"urn:oasis:names:tc:SAML:2.0:protocol"},
      {~c"saml", ~c"urn:oasis:names:tc:SAML:2.0:assertion"}
    ]

    with {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_request),
         nodes when is_list(nodes) and length(nodes) == 1 <-
           :xmerl_xpath.string(~c"/samlp:LogoutRequest", xml_frag, [{:namespace, req_ns}]) do
      :esaml_sp.validate_logout_request(xml_frag, sp)
    else
      _ -> {:error, :invalid_request}
    end
  end

  # Decodes the base64 (and maybe deflated) SAML payload into an xmerl element.
  #
  # Returns `{:error, {:invalid_response, reason}}` for anything that is not
  # well-formed XML. xmerl signals parse failures with `exit/1`, so a plain
  # `rescue` would let a malformed POST crash the request process.
  defp decode_saml_payload(saml_encoding, saml_payload) do
    try do
      xml = :esaml_binding.decode_response(saml_encoding, saml_payload)
      {:ok, xml}
    rescue
      error -> {:error, {:invalid_response, "#{inspect(error)}"}}
    catch
      :exit, reason -> {:error, {:invalid_response, "#{inspect(reason)}"}}
    end
  end
end
