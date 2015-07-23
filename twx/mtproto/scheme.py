try:
    from . coretypes import *
except SystemError:
    from coretypes import *

"""
resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ
"""

ResPQ_t = MTPType('ResPQ_t')

resPQ_c = BareType(name='resPQ_c', number=0x05162463,
    params=['nonce', 'server_nonce', 'pq', 'server_public_key_fingerprints'],
    param_types=[int128_c, int128_c, bytes_c, Vector(long_c)],
    result_type=ResPQ_t)

ResPQ = BoxedType('ResPQ', ResPQ_t)

"""
p_q_inner_data#83c95aec pq:bytes p:bytes q:bytes nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data
"""

P_Q_inner_data_t = MTPType('P_Q_inner_data_t')

p_q_inner_data_c = BareType(name='p_q_inner_data_c', number=0x83c95aec,
    params=['pq', 'p', 'q', 'nonce', 'server_nonce', 'new_nonce'],
    param_types=[bytes_c, bytes_c, bytes_c, int128_c, int128_c, int256_c],
    result_type=P_Q_inner_data_t)

P_Q_inner_data = BoxedType('P_Q_inner_data', P_Q_inner_data_t)

"""
server_DH_params_fail#79cb045d nonce:int128 server_nonce:int128 new_nonce_hash:int128 = Server_DH_Params
server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:bytes = Server_DH_Params
"""

Server_DH_Params_t = MTPType('Server_DH_Params_t')

server_DH_params_fail_c = BareType(name='server_DH_params_fail_c', number=0x79cb045d,
    params=['nonce', 'server_nonce', 'new_nonce_hash'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Server_DH_Params_t)

server_DH_params_ok_c = BareType(name='server_DH_params_ok_c', number=0xd0e8075c,
    params=['nonce', 'server_nonce', 'encrypted_answer'],
    param_types=[int128_c, int128_c, bytes_c],
    result_type=Server_DH_Params_t)

Server_DH_Params = BoxedType('Server_DH_Params', Server_DH_Params_t)

"""
server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:bytes g_a:bytes server_time:int = Server_DH_inner_data
"""

Server_DH_inner_data_t = MTPType('Server_DH_inner_data_t')

server_DH_inner_data_c = BareType(name='server_DH_inner_data_c', number=0xb5890dba,
    params=['nonce', 'server_nonce', 'g', 'dh_prime', 'g_a', 'server_time'],
    param_types=[int128_c, int128_c, int_c, bytes_c, bytes_c, int_c],
    result_type=Server_DH_inner_data_t)

Server_DH_inner_data = BoxedType('Server_DH_inner_data', Server_DH_inner_data_t)

"""
client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:bytes = Client_DH_Inner_Data
"""

Client_DH_Inner_Data_t = MTPType('Client_DH_Inner_Data_t')

client_DH_inner_data_c = BareType(name='client_DH_inner_data_c', number=0x6643b654,
    params=['nonce', 'server_nonce', 'retry_id', 'g_b'],
    param_types=[int128_c, int128_c, long_c, bytes_c],
    result_type=Client_DH_Inner_Data_t)

Client_DH_Inner_Data = BoxedType('Client_DH_Inner_Data', Client_DH_Inner_Data_t)

"""
dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer
dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer
dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer
"""

Set_client_DH_params_answer_t = MTPType('Set_client_DH_params_answer_t')

dh_gen_ok_c = BareType(name='dh_gen_ok_c', number=0x3bcbf734,
    params=['nonce', 'server_nonce', 'new_nonce_hash1'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Set_client_DH_params_answer_t)

dh_gen_retry_c = BareType(name='dh_gen_retry_c', number=0x46dc1fb9,
    params=['nonce', 'server_nonce', 'new_nonce_hash2'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Set_client_DH_params_answer_t)

dh_gen_fail_c = BareType(name='dh_gen_fail_c', number=0xa69dae02,
    params=['nonce', 'server_nonce', 'new_nonce_hash3'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Set_client_DH_params_answer_t)

Set_client_DH_params_answer = BoxedType('Set_client_DH_params_answer', Set_client_DH_params_answer_t)

"""
rpc_result#f35c6d01 req_msg_id:long result:Object = RpcResult
"""

RpcResult_t = MTPType('RpcResult_t')

rpc_result_c = BareType(name='rpc_result_c', number=0xf35c6d01,
    params=['req_msg_id', 'result'],
    param_types=[long_c, object],
    result_type=RpcResult_t)

RpcResult = BoxedType('RpcResult', RpcResult_t)

"""
rpc_error#2144ca19 error_code:int error_message:string = RpcError
"""

RpcError_t = MTPType('RpcError_t')

rpc_error_c = BareType(name='rpc_error_c', number=0x2144ca19,
    params=['error_code', 'error_message'],
    param_types=[int_c, string_c],
    result_type=RpcError_t)

RpcError = BoxedType('RpcError', RpcError_t)

"""
rpc_answer_unknown#5e2ad36e = RpcDropAnswer
rpc_answer_dropped_running#cd78e586 = RpcDropAnswer
rpc_answer_dropped#a43ad8b7 msg_id:long seq_no:int bytes:int = RpcDropAnswer
"""

RpcDropAnswer_t = MTPType('RpcDropAnswer_t')

rpc_answer_unknown_c = BareType(name='rpc_answer_unknown_c', number=0x5e2ad36e,
    params=[],
    param_types=[],
    result_type=RpcDropAnswer_t)

rpc_answer_dropped_running_c = BareType(name='rpc_answer_dropped_running_c', number=0xcd78e586,
    params=[],
    param_types=[],
    result_type=RpcDropAnswer_t)

rpc_answer_dropped_c = BareType(name='rpc_answer_dropped_c', number=0xa43ad8b7,
    params=['msg_id', 'seq_no', 'bytes'],
    param_types=[long_c, int_c, int_c],
    result_type=RpcDropAnswer_t)

RpcDropAnswer = BoxedType('RpcDropAnswer', RpcDropAnswer_t)

"""
future_salt#0949d9dc valid_since:int valid_until:int salt:long = FutureSalt
"""

FutureSalt_t = MTPType('FutureSalt_t')

future_salt_c = BareType(name='future_salt_c', number=0x0949d9dc,
    params=['valid_since', 'valid_until', 'salt'],
    param_types=[int_c, int_c, long_c],
    result_type=FutureSalt_t)

FutureSalt = BoxedType('FutureSalt', FutureSalt_t)

"""
future_salts#ae500895 req_msg_id:long now:int salts:vector<future_salt> = FutureSalts
"""

FutureSalts_t = MTPType('FutureSalts_t')

future_salts_c = BareType(name='future_salts_c', number=0xae500895,
    params=['req_msg_id', 'now', 'salts'],
    param_types=[long_c, int_c, vector_c(future_salt_c)],
    result_type=FutureSalts_t)

FutureSalts = BoxedType('FutureSalts', FutureSalts_t)

"""
pong#347773c5 msg_id:long ping_id:long = Pong
"""

Pong_t = MTPType('Pong_t')

pong_c = BareType(name='pong_c', number=0x347773c5,
    params=['msg_id', 'ping_id'],
    param_types=[long_c, long_c],
    result_type=Pong_t)

Pong = BoxedType('Pong', Pong_t)

"""
destroy_session_ok#e22045fc session_id:long = DestroySessionRes
destroy_session_none#62d350c9 session_id:long = DestroySessionRes
"""

DestroySessionRes_t = MTPType('DestroySessionRes_t')

destroy_session_ok_c = BareType(name='destroy_session_ok_c', number=0xe22045fc,
    params=['session_id'],
    param_types=[long_c],
    result_type=DestroySessionRes_t)

destroy_session_none_c = BareType(name='destroy_session_none_c', number=0x62d350c9,
    params=['session_id'],
    param_types=[long_c],
    result_type=DestroySessionRes_t)

DestroySessionRes = BoxedType('DestroySessionRes', DestroySessionRes_t)

"""
new_session_created#9ec20908 first_msg_id:long unique_id:long server_salt:long = NewSession
"""

NewSession_t = MTPType('NewSession_t')

new_session_created_c = BareType(name='new_session_created_c', number=0x9ec20908,
    params=['first_msg_id', 'unique_id', 'server_salt'],
    param_types=[long_c, long_c, long_c],
    result_type=NewSession_t)

NewSession = BoxedType('NewSession', NewSession_t)

"""
message msg_id:long seqno:int bytes:int body:Object = Message
"""

Message_t = MTPType('Message_t')

message_c = BareType(name='message_c', number=crc32('message msg_id:long seqno:int bytes:int body:Object = Message'.encode()),
    params=['msg_id', 'seqno', 'bytes', 'body'],
    param_types=[long_c, int_c, int_c, object],
    result_type=Message_t)

Message = BoxedType('Message', Message_t)

"""
msg_container#73f1f8dc messages:vector<%Message> = MessageContainer
"""

MessageContainer_t = MTPType('MessageContainer_t')

msg_container_c = BareType(name='msg_container_c', number=0x73f1f8dc,
    params=['messages'],
    param_types=[vector_c(message_c)],
    result_type=MessageContainer_t)

MessageContainer = BoxedType('MessageContainer', MessageContainer_t)

"""
msg_copy#e06046b2 orig_message:Message = MessageCopy
"""

MessageCopy_t = MTPType('MessageCopy_t')

msg_copy_c = BareType(name='msg_copy_c', number=0xe06046b2,
    params=['orig_message'],
    param_types=[Message],
    result_type=MessageCopy_t)

MessageCopy = BoxedType('MessageCopy', MessageCopy_t)

"""
gzip_packed#3072cfa1 packed_data:bytes = Object
"""

TLType_t = MTPType('TLType_t')

gzip_packed_c = BareType(name='gzip_packed_c', number=0x3072cfa1,
    params=['packed_data'],
    param_types=[bytes_c],
    result_type=TLType_t)

TLType = BoxedType('TLType', TLType_t)

"""
msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck
"""

MsgsAck_t = MTPType('MsgsAck_t')

msgs_ack_c = BareType(name='msgs_ack_c', number=0x62d6b459,
    params=['msg_ids'],
    param_types=[Vector(long_c)],
    result_type=MsgsAck_t)

MsgsAck = BoxedType('MsgsAck', MsgsAck_t)

"""
bad_msg_notification#a7eff811 bad_msg_id:long bad_msg_seqno:int error_code:int = BadMsgNotification
bad_server_salt#edab447b bad_msg_id:long bad_msg_seqno:int error_code:int new_server_salt:long = BadMsgNotification
"""

BadMsgNotification_t = MTPType('BadMsgNotification_t')

bad_msg_notification_c = BareType(name='bad_msg_notification_c', number=0xa7eff811,
    params=['bad_msg_id', 'bad_msg_seqno', 'error_code'],
    param_types=[long_c, int_c, int_c],
    result_type=BadMsgNotification_t)

bad_server_salt_c = BareType(name='bad_server_salt_c', number=0xedab447b,
    params=['bad_msg_id', 'bad_msg_seqno', 'error_code', 'new_server_salt'],
    param_types=[long_c, int_c, int_c, long_c],
    result_type=BadMsgNotification_t)

BadMsgNotification = BoxedType('BadMsgNotification', BadMsgNotification_t)

"""
msg_resend_req#7d861a08 msg_ids:Vector<long> = MsgResendReq
"""

MsgResendReq_t = MTPType('MsgResendReq_t')

msg_resend_req_c = BareType(name='msg_resend_req_c', number=0x7d861a08,
    params=['msg_ids'],
    param_types=[Vector(long_c)],
    result_type=MsgResendReq_t)

MsgResendReq = BoxedType('MsgResendReq', MsgResendReq_t)

"""
msgs_state_req#da69fb52 msg_ids:Vector<long> = MsgsStateReq
"""

MsgsStateReq_t = MTPType('MsgsStateReq_t')

msgs_state_req_c = BareType(name='msgs_state_req_c', number=0xda69fb52,
    params=['msg_ids'],
    param_types=[Vector(long_c)],
    result_type=MsgsStateReq_t)

MsgsStateReq = BoxedType('MsgsStateReq', MsgsStateReq_t)

"""
msgs_state_info#04deb57d req_msg_id:long info:bytes = MsgsStateInfo
"""

MsgsStateInfo_t = MTPType('MsgsStateInfo_t')

msgs_state_info_c = BareType(name='msgs_state_info_c', number=0x04deb57d,
    params=['req_msg_id', 'info'],
    param_types=[long_c, bytes_c],
    result_type=MsgsStateInfo_t)

MsgsStateInfo = BoxedType('MsgsStateInfo', MsgsStateInfo_t)

"""
msgs_all_info#8cc0d131 msg_ids:Vector<long> info:bytes = MsgsAllInfo
"""

MsgsAllInfo_t = MTPType('MsgsAllInfo_t')

msgs_all_info_c = BareType(name='msgs_all_info_c', number=0x8cc0d131,
    params=['msg_ids', 'info'],
    param_types=[Vector(long_c), bytes_c],
    result_type=MsgsAllInfo_t)

MsgsAllInfo = BoxedType('MsgsAllInfo', MsgsAllInfo_t)

"""
msg_detailed_info#276d3ec6 msg_id:long answer_msg_id:long bytes:int status:int = MsgDetailedInfo
"""

MsgDetailedInfo_t = MTPType('MsgDetailedInfo_t')

msg_detailed_info_c = BareType(name='msg_detailed_info_c', number=0x276d3ec6,
    params=['msg_id', 'answer_msg_id', 'bytes', 'status'],
    param_types=[long_c, long_c, int_c, int_c],
    result_type=MsgDetailedInfo_t)

MsgDetailedInfo = BoxedType('MsgDetailedInfo', MsgDetailedInfo_t)

if __name__ == '__main__':
    res_pq_test = resPQ_c(1, 2, b'test1', [10, 20, 30, 40, 50])
    print(res_pq_test)
    print(res_pq_test.hex_list())
    print(res_pq_test.get_bytes())
    print()

    ResPQ_test = ResPQ(res_pq_test)
    print(ResPQ_test)
    print(ResPQ_test.hex_list())
    print(ResPQ_test.get_bytes())
