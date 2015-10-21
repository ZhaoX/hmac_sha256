-module(hmac_sha256).

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

  HashIPad = sha256(IPad),
  sha256(<<OPad/binary, HashIPad/binary, Msg/binary>>). 

binary_to_hex(Data) when is_binary(Data) ->
  leo_hex:bianry_to_hex(Data).
  
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
