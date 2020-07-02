defmodule Samly.RouterUtil do
  @moduledoc false

  alias Plug.Conn
  require Logger
  require Samly.Esaml
  alias Samly.{Esaml, IdpData, Helper}

  @subdomain_re ~r/^(?<subdomain>([^.]+))?\./

  def check_idp_id(conn, _opts) do
    idp_id_from = Application.get_env(:samly, :idp_id_from)

    idp_id =
      if idp_id_from == :subdomain do
        case Regex.named_captures(@subdomain_re, conn.host) do
          %{"subdomain" => idp_id} -> idp_id
          _ -> nil
        end
      else
        case conn.params["idp_id_seg"] do
          [idp_id] -> idp_id
          _ -> nil
        end
      end

    idp = idp_id && Helper.get_idp(idp_id)

    if idp do
      conn |> Conn.put_private(:samly_idp, idp)
    else
      conn |> Conn.send_resp(403, "invalid_request unknown IdP") |> Conn.halt()
    end
  end

  def check_target_url(conn, _opts) do
    try do
      target_url = conn.params["target_url"] && URI.decode_www_form(conn.params["target_url"])
      conn |> Conn.put_private(:samly_target_url, target_url)
    rescue
      ArgumentError ->
        Logger.error(
          "[Samly] target_url must be x-www-form-urlencoded: #{inspect(conn.params["target_url"])}"
        )

        conn |> Conn.send_resp(400, "target_url must be x-www-form-urlencoded") |> Conn.halt()
    end
  end

  # generate URIs using the idp_id
  @spec ensure_sp_uris_set(tuple, Conn.t()) :: tuple
  def ensure_sp_uris_set(sp, conn) do
    case Esaml.esaml_sp(sp, :metadata_uri) do
      [?/ | _] ->
        uri = %URI{
          scheme: Atom.to_string(conn.scheme),
          host: conn.host,
          port: conn.port,
          path: "/sso"
        }

        base_url = URI.to_string(uri)
        idp_id_from = Application.get_env(:samly, :idp_id_from)

        path_segment_idp_id =
          if idp_id_from == :subdomain do
            nil
          else
            %IdpData{id: idp_id} = conn.private[:samly_idp]
            idp_id
          end

        Esaml.esaml_sp(
          sp,
          metadata_uri: Helper.get_metadata_uri(base_url, path_segment_idp_id),
          consume_uri: Helper.get_consume_uri(base_url, path_segment_idp_id),
          logout_uri: Helper.get_logout_uri(base_url, path_segment_idp_id)
        )

      _ ->
        sp
    end
  end

  def send_saml_request(conn, idp_url, use_redirect?, signed_xml_payload, relay_state) do
    if use_redirect? do
      url =
        :esaml_binding.encode_http_redirect(idp_url, signed_xml_payload, :undefined, relay_state)

      conn |> redirect(302, url)
    else
      nonce = conn.private[:samly_nonce]
      resp_body = :esaml_binding.encode_http_post(idp_url, signed_xml_payload, relay_state, nonce)

      conn
      |> Conn.put_resp_header("content-type", "text/html")
      |> Conn.send_resp(200, resp_body)
    end
  end

  def redirect(conn, status_code, dest) do
    conn
    |> Conn.put_resp_header("location", URI.encode(dest))
    |> Conn.send_resp(status_code, "")
    |> Conn.halt()
  end

  @doc """
  Use our own named cookie with SameSite: None for storing relay_state, etc.

  With browsers defaulting to SameSite: Lax for cookies, simply storing the
  relay_state in the Session will fail when the IdP does a POST back to our
  original site (i.e. Service Provider). Cookies are *not* included when
  SameSite is set to lax, and so the relay_state will never match.

  Instead, we set our own cookie with SameSite set to None.
  The cookie is encrypted and given a max age of 90 seconds (in case they need
  to go through their own auth flow before being redirect).
  Since SameSite is None, Secure must be set to true; JS does not need
  this cookie (and couldn't read it anyway), so Http Only is also set to true.
  """
  def set_samly_cookie(conn, idp_id, data) do
    opts = [encrypt: true, max_age: 90, http_only: true, secure: true, same_site: "None"]

    Conn.put_resp_cookie(conn, cookie_name(idp_id), data, opts)
  end

  @doc """
  Use a cookie prefix in the cookie name for additional security

  See https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Cookie_prefixes
  """
  def cookie_name(idp_id), do: "_Host-#{idp_id}_samly"
end
