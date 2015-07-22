from coretypes import *

"""
resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ;
"""
resPQ_c = BareType(name='resPQ', number=0x05162463,
    params=('nonce', 'server_nonce', 'pq', 'server_public_key_fingerprints',),
    param_types=(int128_c, int128_c, bytes_c, Vector(long_c),),
    result='ResPQ'
    )

ResPQ = BoxedType('ResPQ', resPQ_c)

"""
p_q_inner_data#83c95aec pq:bytes p:bytes q:bytes nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data;

"""
p_q_inner_data_c = BareType(
    name='p_q_inner_data_c', number=0x83c95aec,
    params=['pq', 'p', 'q', 'nonce', 'server_nonce', 'new_nonce'],
    param_types=[bytes_c, bytes_c, bytes_c, int128_c, int128_c, int256_c],
    result='P_Q_inner_data')

P_Q_inner_data = BoxedType('P_Q_inner_data', p_q_inner_data_c)

test_resPQ = resPQ_c(1, 2, b'test', server_public_key_fingerprints=[4])
test_ResPQ = ResPQ(1, 2, b'test', server_public_key_fingerprints=[4])

pq_inner_data = p_q_inner_data_c(b'pq', b'p', b'q', 10, 20, 30)
PQ_inner_data = P_Q_inner_data(b'pq', b'p', b'q', 10, 20, 30)

test_string = string_c("test")
test_bytes = bytes_c("test")

print(pq_inner_data)
print(PQ_inner_data)
print()

print(pq_inner_data.hex_list())
print(PQ_inner_data.hex_list())
print()

print(pq_inner_data.get_bytes())
print(PQ_inner_data.get_bytes())
