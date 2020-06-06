defmodule Samly.SPHandler do
  @moduledoc false

  require Logger
  import Plug.Conn
  alias Plug.Conn
  require Samly.Esaml
  alias Samly.{Assertion, Esaml, Helper, IdpData, RouterUtil, State, Subject}

  def send_metadata(conn) do
    %IdpData{} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = RouterUtil.ensure_sp_uris_set(sp_rec, conn)
    metadata = Helper.sp_metadata(sp)

    conn
    |> put_resp_header("content-type", "text/xml")
    |> send_resp(200, metadata)

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  def consume_signin_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{pre_session_create_pipeline: pipeline, esaml_sp_rec: sp_rec} = idp
    sp = RouterUtil.ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]
    relay_state = conn.body_params["RelayState"] |> URI.decode_www_form()

    with {:ok, assertion} <- Helper.decode_idp_auth_resp(sp, saml_encoding, saml_response),
         :ok <- validate_authresp(conn, assertion, relay_state),
         conn = conn |> put_private(:samly_assertion, assertion),
         {:halted, %Conn{halted: false} = conn} <- {:halted, pipethrough(conn, pipeline)} do
      updated_assertion = conn.private[:samly_assertion]
      computed = updated_assertion.computed
      assertion = %Assertion{assertion | computed: computed, idp_id: idp_id}

      nameid = assertion.subject.name
      assertion_key = {idp_id, nameid}
      conn = State.put_assertion(conn, assertion_key, assertion)
      target_url = auth_target_url(conn, assertion, relay_state)

      conn
      |> configure_session(renew: true)
      |> put_session("samly_assertion_key", assertion_key)
      |> RouterUtil.redirect(302, target_url)
    else
      {:halted, conn} -> conn
      {:error, reason} -> conn |> send_resp(403, "access_denied #{inspect(reason)}")
      _ -> conn |> send_resp(403, "access_denied")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # IDP-initiated flow auth response
  @spec validate_authresp(Conn.t(), Assertion.t(), binary) :: :ok | {:error, atom}
  defp validate_authresp(conn, %{subject: %{in_response_to: ""}}, relay_state) do
    idp_data = conn.private[:samly_idp]

    if idp_data.allow_idp_initiated_flow do
      if idp_data.allowed_target_urls do
        if relay_state in idp_data.allowed_target_urls do
          :ok
        else
          {:error, :invalid_target_url}
        end
      else
        :ok
      end
    else
      {:error, :idp_first_flow_not_allowed}
    end
  end

  # SP-initiated flow auth response
  defp validate_authresp(conn, _assertion, relay_state) do
    %IdpData{id: idp_id} = conn.private[:samly_idp]

    cookie_name = RouterUtil.cookie_name(idp_id)
    conn = fetch_cookies(conn, encrypted: cookie_name)
    samly_cookie = Map.get(conn.cookies, cookie_name, %{})

    rs_in_cookie = Map.get(samly_cookie, :relay_state)
    idp_id_in_cookie = Map.get(samly_cookie, :idp_id)
    url_in_cookie = Map.get(samly_cookie, :target_url)

    cond do
      rs_in_cookie == nil || rs_in_cookie != relay_state ->
        {:error, :invalid_relay_state}

      idp_id_in_cookie == nil || idp_id_in_cookie != idp_id ->
        {:error, :invalid_idp_id}

      url_in_cookie == nil ->
        {:error, :invalid_target_url}

      true ->
        :ok
    end
  end

  defp pipethrough(conn, nil), do: conn

  defp pipethrough(conn, pipeline) do
    pipeline.call(conn, [])
  end

  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, ""), do: "/"
  defp auth_target_url(_conn, %{subject: %{in_response_to: ""}}, url), do: url

  defp auth_target_url(conn, _assertion, _relay_state) do
    get_session(conn, "target_url") || "/"
  end

  def handle_logout_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = RouterUtil.ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]
    relay_state = conn.body_params["RelayState"] |> URI.decode_www_form()

    cookie_name = RouterUtil.cookie_name(idp_id)
    conn = fetch_cookies(conn, encrypted: cookie_name)
    samly_cookie = Map.get(conn.cookies, cookie_name, %{})

    with(
      {:ok, _payload} <- Helper.decode_idp_signout_resp(sp, saml_encoding, saml_response),
      ^relay_state when relay_state != nil <- Map.get(samly_cookie, :relay_state),
      ^idp_id <- Map.get(samly_cookie, :idp_id),
      target_url when target_url != nil <- Map.get(samly_cookie, :target_url)
    ) do
      conn
      |> configure_session(drop: true)
      |> RouterUtil.redirect(302, target_url)
    else
      error -> conn |> send_resp(403, "invalid_request #{inspect(error)}")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # non-ui logout request from IDP
  def handle_logout_request(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = RouterUtil.ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_request = conn.body_params["SAMLRequest"]
    relay_state = conn.body_params["RelayState"] |> URI.decode_www_form()

    with {:ok, payload} <- Helper.decode_idp_signout_req(sp, saml_encoding, saml_request) do
      Esaml.esaml_logoutreq(name: nameid, issuer: _issuer) = payload
      assertion_key = {idp_id, nameid}

      {conn, return_status} =
        case State.get_assertion(conn, assertion_key) do
          %Assertion{idp_id: ^idp_id, subject: %Subject{name: ^nameid}} ->
            conn = State.delete_assertion(conn, assertion_key)
            {conn, :success}

          _ ->
            {conn, :denied}
        end

      {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_rec, return_status)

      conn
      |> configure_session(drop: true)
      |> RouterUtil.send_saml_request(idp_signout_url, idp.use_redirect_for_req,
        resp_xml_frag, relay_state)
    else
      error ->
        Logger.error("#{inspect(error)}")
        {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_rec, :denied)

        conn
        |> RouterUtil.send_saml_request(idp_signout_url, idp.use_redirect_for_req,
          resp_xml_frag, relay_state)
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end
end
