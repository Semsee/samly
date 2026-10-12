%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc SAML HTTP binding handlers
-module(esaml_binding).

-export([decode_response/2, encode_http_redirect/4, encode_http_post/3, encode_http_post/4]).

-include_lib("xmerl/include/xmerl.hrl").
-define(deflate, <<"urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE">>).

%% Hard cap on the size of an inflated SAML message. Real-world responses are
%% tens of kilobytes; anything approaching this limit is a decompression bomb.
-define(max_inflated_bytes, 1024 * 1024).

-type uri() :: binary() | string().
-type html_doc() :: binary().
-type xml() :: #xmlElement{} | #xmlDocument{}.

%% @private
-spec xml_payload_type(xml()) -> binary().
xml_payload_type(Xml) ->
    case Xml of
        #xmlDocument{content = [#xmlElement{name = Atom}]} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        #xmlElement{name = Atom} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        _ -> <<"SAMLRequest">>
    end.

%% @doc Unpack and parse a SAMLResponse with given encoding
-spec decode_response(SAMLEncoding :: binary(), SAMLResponse :: binary()) -> #xmlDocument{}.
decode_response(?deflate, SAMLResponse) ->
    XmlData = binary_to_list(safe_unzip(base64:decode(SAMLResponse))),
    scan_untrusted(XmlData);
decode_response(_, SAMLResponse) ->
    Data = base64:decode(SAMLResponse),
    %% HTTP-POST payloads are normally plain XML, but some IdPs deflate them too.
    XmlData = try safe_unzip(Data) of
        Bin -> binary_to_list(Bin)
    catch
        _:_ -> binary_to_list(Data)
    end,
    scan_untrusted(XmlData).

%% @private
%% Parses XML that came from the network, with entity expansion disabled.
%%
%% Expanding entities before the signature is checked lets an attacker read
%% local files or reach internal hosts (CVE-2026-28809). OTP 27+ already
%% defaults to this, the explicit option keeps older releases safe too.
-spec scan_untrusted(string()) -> #xmlElement{}.
scan_untrusted(XmlData) ->
    {Xml, _} = xmerl_scan:string(XmlData, [{namespace_conformant, true}, {allow_entities, false}]),
    Xml.

%% @private
%% Inflates a raw-DEFLATE payload, refusing to grow past ?max_inflated_bytes.
%%
%% zlib:unzip/1 allocates whatever the stream expands to, so a few kilobytes of
%% crafted input could exhaust memory on the SP before any validation runs.
%% Raises error(inflated_payload_too_large) when the cap is exceeded.
-spec safe_unzip(binary()) -> binary().
safe_unzip(Compressed) ->
    Z = zlib:open(),
    try
        ok = zlib:inflateInit(Z, -15),
        Inflated = safe_inflate_loop(Z, zlib:safeInflate(Z, Compressed), [], 0),
        ok = zlib:inflateEnd(Z),
        Inflated
    after
        zlib:close(Z)
    end.

safe_inflate_loop(Z, {Status, Chunk}, Acc, Size) ->
    NewSize = Size + iolist_size(Chunk),
    if NewSize > ?max_inflated_bytes -> error(inflated_payload_too_large);
       true -> ok
    end,
    NewAcc = [Acc, Chunk],
    case Status of
        finished -> iolist_to_binary(NewAcc);
        continue -> safe_inflate_loop(Z, zlib:safeInflate(Z, []), NewAcc, NewSize)
    end.

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-Redirect binding
%%
%% Returns the URI that should be the target of redirection.
-spec encode_http_redirect(IDPTarget :: uri(), SignedXml :: xml(), Username :: undefined | string(), RelayState :: binary()) -> uri().
encode_http_redirect(IdpTarget, SignedXml, Username, RelayState) ->
  Type = xml_payload_type(SignedXml),
  Req = lists:flatten(xmerl:export([SignedXml], xmerl_xml)),

  QueryList = [
               {"SAMLEncoding", ?deflate},
               {Type, base64:encode_to_string(zlib:zip(Req))},
               {"RelayState", uri_string:normalize(binary_to_list(RelayState))}
              ],
  QueryParamStr = uri_string:compose_query(QueryList),
  FirstParamDelimiter = case lists:member($?, IdpTarget) of true -> "&"; false -> "?" end,
  Username_Part = redirect_username_part(Username),

  iolist_to_binary([IdpTarget, FirstParamDelimiter, QueryParamStr | Username_Part]).

redirect_username_part(Username) when is_binary(Username), size(Username) > 0 ->
  ["&", uri_string:compose_query([{"username", uri_string:normalize(binary_to_list(Username))}])];
redirect_username_part(_Other) -> [].

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-POST binding
%%
%% Returns the HTML document to be sent to the browser, containing a
%% form and javascript to automatically submit it.
-spec encode_http_post(IDPTarget :: uri(), SignedXml :: xml(), RelayState :: binary()) -> html_doc().
encode_http_post(IdpTarget, SignedXml, RelayState) ->
    encode_http_post(IdpTarget, SignedXml, RelayState, <<>>).

-spec encode_http_post(IDPTarget :: uri(), SignedXml :: xml(), RelayState :: binary(), Nonce :: binary()) -> html_doc().
encode_http_post(IdpTarget, SignedXml, RelayState, Nonce) when is_binary(Nonce) ->
    Type = xml_payload_type(SignedXml),
	Req = lists:flatten(xmerl:export([SignedXml], xmerl_xml)),
    generate_post_html(Type, IdpTarget, base64:encode(Req), RelayState, Nonce).

generate_post_html(Type, Dest, Req, RelayState, Nonce) ->
    NonceFragment = case Nonce of
        <<>> -> <<>>;
        _ -> [<<"nonce=\"">>, Nonce, <<"\"">>]
    end,
    iolist_to_binary([<<"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
<head>
<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />
<title>POST data</title>
</head>
<body>
<script ">>,NonceFragment,<<">
document.addEventListener('DOMContentLoaded', function () {
document.getElementById('saml-req-form').submit();
});
</script>
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form id=\"saml-req-form\" method=\"post\" action=\"">>,Dest,<<"\">
<input type=\"hidden\" name=\"">>,Type,<<"\" value=\"">>,Req,<<"\" />
<input type=\"hidden\" name=\"RelayState\" value=\"">>,RelayState,<<"\" />
<noscript><input type=\"submit\" value=\"Submit\" /></noscript>
</form>
</body>
</html>">>]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.
