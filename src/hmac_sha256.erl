%%---------------------------------------------------------------------------------
%% @reference https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
%%---------------------------------------------------------------------------------
-module(hmac_sha256).

-author('Xin Zhao').
-include_lib("eunit/include/eunit.hrl").

-export([mac/2,
         binary_to_hex/1]).

mac(Key, Msg) when is_binary(Key) and is_binary(Msg) ->
  BlockSize = 64,
  Key1 = case byte_size(Key) > BlockSize of
    true ->
      sha256(Key);
    false ->
      Key
  end, 

  Key2 = pad_key(Key1, BlockSize),

  OPad = list_to_binary([X bxor 16#5c || X <- binary_to_list(Key2)]),
  IPad = list_to_binary([X bxor 16#36 || X <- binary_to_list(Key2)]),

  HashIPad = sha256(<<IPad/binary, Msg/binary>>),
  sha256(<<OPad/binary, HashIPad/binary>>). 

binary_to_hex(Data) when is_binary(Data) ->
  leo_hex:binary_to_hex(Data).
  
%%---------------------------------------------------------------------------------
%% internal functions
%%---------------------------------------------------------------------------------

sha256(Value) ->
  Contex0 = crypto:sha256_init(),
  Contex = crypto:sha256_update(Contex0, Value),
  crypto:sha256_final(Contex).

pad_key(Key, BlockSize) when byte_size(Key) == BlockSize ->
  Key;
pad_key(Key, BlockSize) when byte_size(Key) < BlockSize ->
  pad_key(<<Key/binary, "\0">>, BlockSize).

%%---------------------------------------------------------------------------------
%% tests
%%---------------------------------------------------------------------------------
mac_test() ->
  ?assertEqual("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", hmac_sha256:binary_to_hex(hmac_sha256:mac(<<>>, <<>>))),
  ?assertEqual("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", hmac_sha256:binary_to_hex(hmac_sha256:mac(<<"key">>, <<"The quick brown fox jumps over the lazy dog">>))),
  ok.

