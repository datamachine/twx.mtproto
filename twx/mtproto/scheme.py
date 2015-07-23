from coretypes import *

"""
resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ
"""

class ResPQ_type:
    _constructors = dict()

resPQ_c = BareType(name='resPQ_c', number=0x05162463,
    params=['nonce', 'server_nonce', 'pq', 'server_public_key_fingerprints'],
    param_types=[int128_c, int128_c, bytes_c, Vector(long_c)],
    result_type=ResPQ_type)

ResPQ = BoxedType.new('ResPQ', ResPQ_type)

"""
p_q_inner_data#83c95aec pq:bytes p:bytes q:bytes nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data
"""

class P_Q_inner_data_type:
    _constructors = dict()

p_q_inner_data_c = BareType(name='p_q_inner_data_c', number=0x83c95aec,
    params=['pq', 'p', 'q', 'nonce', 'server_nonce', 'new_nonce'],
    param_types=[bytes_c, bytes_c, bytes_c, int128_c, int128_c, int256_c],
    result_type=P_Q_inner_data_type)

P_Q_inner_data = BoxedType.new('P_Q_inner_data', P_Q_inner_data_type)

"""
server_DH_params_fail#79cb045d nonce:int128 server_nonce:int128 new_nonce_hash:int128 = Server_DH_Params
server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:bytes = Server_DH_Params
"""

class Server_DH_Params_type:
    _constructors = dict()

server_DH_params_fail_c = BareType(name='server_DH_params_fail_c', number=0x79cb045d,
    params=['nonce', 'server_nonce', 'new_nonce_hash'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Server_DH_Params_type)

server_DH_params_ok_c = BareType(name='server_DH_params_ok_c', number=0xd0e8075c,
    params=['nonce', 'server_nonce', 'encrypted_answer'],
    param_types=[int128_c, int128_c, bytes_c],
    result_type=Server_DH_Params_type)

Server_DH_Params = BoxedType.new('Server_DH_Params', Server_DH_Params_type)

"""
server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:bytes g_a:bytes server_time:int = Server_DH_inner_data
"""

class Server_DH_inner_data_type:
    _constructors = dict()

server_DH_inner_data_c = BareType(name='server_DH_inner_data_c', number=0xb5890dba,
    params=['nonce', 'server_nonce', 'g', 'dh_prime', 'g_a', 'server_time'],
    param_types=[int128_c, int128_c, int_c, bytes_c, bytes_c, int_c],
    result_type=Server_DH_inner_data_type)

Server_DH_inner_data = BoxedType.new('Server_DH_inner_data', Server_DH_inner_data_type)

"""
client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:bytes = Client_DH_Inner_Data
"""

class Client_DH_Inner_Data_type:
    _constructors = dict()

client_DH_inner_data_c = BareType(name='client_DH_inner_data_c', number=0x6643b654,
    params=['nonce', 'server_nonce', 'retry_id', 'g_b'],
    param_types=[int128_c, int128_c, long_c, bytes_c],
    result_type=Client_DH_Inner_Data_type)

Client_DH_Inner_Data = BoxedType.new('Client_DH_Inner_Data', Client_DH_Inner_Data_type)

"""
dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer
dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer
dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer
"""

class Set_client_DH_params_answer_type:
    _constructors = dict()

dh_gen_ok_c = BareType(name='dh_gen_ok_c', number=0x3bcbf734,
    params=['nonce', 'server_nonce', 'new_nonce_hash1'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Set_client_DH_params_answer_type)

dh_gen_retry_c = BareType(name='dh_gen_retry_c', number=0x46dc1fb9,
    params=['nonce', 'server_nonce', 'new_nonce_hash2'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Set_client_DH_params_answer_type)

dh_gen_fail_c = BareType(name='dh_gen_fail_c', number=0xa69dae02,
    params=['nonce', 'server_nonce', 'new_nonce_hash3'],
    param_types=[int128_c, int128_c, int128_c],
    result_type=Set_client_DH_params_answer_type)

Set_client_DH_params_answer = BoxedType.new('Set_client_DH_params_answer', Set_client_DH_params_answer_type)

"""
rpc_result#f35c6d01 req_msg_id:long result:Object = RpcResult
"""

class RpcResult_type:
    _constructors = dict()

rpc_result_c = BareType(name='rpc_result_c', number=0xf35c6d01,
    params=['req_msg_id', 'result'],
    param_types=[long_c, object],
    result_type=RpcResult_type)

RpcResult = BoxedType.new('RpcResult', RpcResult_type)

"""
rpc_error#2144ca19 error_code:int error_message:string = RpcError
"""

class RpcError_type:
    _constructors = dict()

rpc_error_c = BareType(name='rpc_error_c', number=0x2144ca19,
    params=['error_code', 'error_message'],
    param_types=[int_c, string_c],
    result_type=RpcError_type)

RpcError = BoxedType.new('RpcError', RpcError_type)

"""
rpc_answer_unknown#5e2ad36e = RpcDropAnswer
rpc_answer_dropped_running#cd78e586 = RpcDropAnswer
rpc_answer_dropped#a43ad8b7 msg_id:long seq_no:int bytes:int = RpcDropAnswer
"""

class RpcDropAnswer_type:
    _constructors = dict()

rpc_answer_unknown_c = BareType(name='rpc_answer_unknown_c', number=0x5e2ad36e,
    params=[],
    param_types=[],
    result_type=RpcDropAnswer_type)

rpc_answer_dropped_running_c = BareType(name='rpc_answer_dropped_running_c', number=0xcd78e586,
    params=[],
    param_types=[],
    result_type=RpcDropAnswer_type)

rpc_answer_dropped_c = BareType(name='rpc_answer_dropped_c', number=0xa43ad8b7,
    params=['msg_id', 'seq_no', 'bytes'],
    param_types=[long_c, int_c, int_c],
    result_type=RpcDropAnswer_type)

RpcDropAnswer = BoxedType.new('RpcDropAnswer', RpcDropAnswer_type)

"""
future_salt#0949d9dc valid_since:int valid_until:int salt:long = FutureSalt
"""

class FutureSalt_type:
    _constructors = dict()

future_salt_c = BareType(name='future_salt_c', number=0x0949d9dc,
    params=['valid_since', 'valid_until', 'salt'],
    param_types=[int_c, int_c, long_c],
    result_type=FutureSalt_type)

FutureSalt = BoxedType.new('FutureSalt', FutureSalt_type)

"""
future_salts#ae500895 req_msg_id:long now:int salts:vector<future_salt> = FutureSalts
"""

class FutureSalts_type:
    _constructors = dict()

future_salts_c = BareType(name='future_salts_c', number=0xae500895,
    params=['req_msg_id', 'now', 'salts'],
    param_types=[long_c, int_c, vector_c(future_salt_c)],
    result_type=FutureSalts_type)

FutureSalts = BoxedType.new('FutureSalts', FutureSalts_type)

"""
pong#347773c5 msg_id:long ping_id:long = Pong
"""

class Pong_type:
    _constructors = dict()

pong_c = BareType(name='pong_c', number=0x347773c5,
    params=['msg_id', 'ping_id'],
    param_types=[long_c, long_c],
    result_type=Pong_type)

Pong = BoxedType.new('Pong', Pong_type)

"""
destroy_session_ok#e22045fc session_id:long = DestroySessionRes
destroy_session_none#62d350c9 session_id:long = DestroySessionRes
"""

class DestroySessionRes_type:
    _constructors = dict()

destroy_session_ok_c = BareType(name='destroy_session_ok_c', number=0xe22045fc,
    params=['session_id'],
    param_types=[long_c],
    result_type=DestroySessionRes_type)

destroy_session_none_c = BareType(name='destroy_session_none_c', number=0x62d350c9,
    params=['session_id'],
    param_types=[long_c],
    result_type=DestroySessionRes_type)

DestroySessionRes = BoxedType.new('DestroySessionRes', DestroySessionRes_type)

"""
new_session_created#9ec20908 first_msg_id:long unique_id:long server_salt:long = NewSession
"""

class NewSession_type:
    _constructors = dict()

new_session_created_c = BareType(name='new_session_created_c', number=0x9ec20908,
    params=['first_msg_id', 'unique_id', 'server_salt'],
    param_types=[long_c, long_c, long_c],
    result_type=NewSession_type)

NewSession = BoxedType.new('NewSession', NewSession_type)


"""
message msg_id:long seqno:int bytes:int body:Object = Message
"""

class Message_type:
    _constructors = dict()

message_c = BareType(name='message_c', number=crc32('message msg_id:long seqno:int bytes:int body:Object = Message'.encode()),
    params=['msg_id', 'seqno', 'bytes', 'body'],
    param_types=[long_c, int_c, int_c, object],
    result_type=Message_type)

Message = BoxedType.new('Message', Message_type)

"""
msg_container#73f1f8dc messages:vector<%Message> = MessageContainer
"""

class MessageContainer_type:
    _constructors = dict()

msg_container_c = BareType(name='msg_container_c', number=0x73f1f8dc,
    params=['messages'],
    param_types=[vector_c(message_c)],
    result_type=MessageContainer_type)

MessageContainer = BoxedType.new('MessageContainer', MessageContainer_type)

"""
msg_copy#e06046b2 orig_message:Message = MessageCopy
"""

class MessageCopy_type:
    _constructors = dict()

msg_copy_c = BareType(name='msg_copy_c', number=0xe06046b2,
    params=['orig_message'],
    param_types=[Message],
    result_type=MessageCopy_type)

MessageCopy = BoxedType.new('MessageCopy', MessageCopy_type)

"""
gzip_packed#3072cfa1 packed_data:bytes = Object
"""

class TLType_type:
    _constructors = dict()

gzip_packed_c = BareType(name='gzip_packed_c', number=0x3072cfa1,
    params=['packed_data'],
    param_types=[bytes_c],
    result_type=TLType_type)

TLType = BoxedType.new('TLType', TLType_type)

"""
msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck
"""

class MsgsAck_type:
    _constructors = dict()

msgs_ack_c = BareType(name='msgs_ack_c', number=0x62d6b459,
    params=['msg_ids'],
    param_types=[Vector(long_c)],
    result_type=MsgsAck_type)

MsgsAck = BoxedType.new('MsgsAck', MsgsAck_type)

"""
bad_msg_notification#a7eff811 bad_msg_id:long bad_msg_seqno:int error_code:int = BadMsgNotification
bad_server_salt#edab447b bad_msg_id:long bad_msg_seqno:int error_code:int new_server_salt:long = BadMsgNotification
"""

class BadMsgNotification_type:
    _constructors = dict()

bad_msg_notification_c = BareType(name='bad_msg_notification_c', number=0xa7eff811,
    params=['bad_msg_id', 'bad_msg_seqno', 'error_code'],
    param_types=[long_c, int_c, int_c],
    result_type=BadMsgNotification_type)

bad_server_salt_c = BareType(name='bad_server_salt_c', number=0xedab447b,
    params=['bad_msg_id', 'bad_msg_seqno', 'error_code', 'new_server_salt'],
    param_types=[long_c, int_c, int_c, long_c],
    result_type=BadMsgNotification_type)

BadMsgNotification = BoxedType.new('BadMsgNotification', BadMsgNotification_type)

"""
msg_resend_req#7d861a08 msg_ids:Vector<long> = MsgResendReq
"""

class MsgResendReq_type:
    _constructors = dict()

msg_resend_req_c = BareType(name='msg_resend_req_c', number=0x7d861a08,
    params=['msg_ids'],
    param_types=[Vector(long_c)],
    result_type=MsgResendReq_type)

MsgResendReq = BoxedType.new('MsgResendReq', MsgResendReq_type)

"""
msgs_state_req#da69fb52 msg_ids:Vector<long> = MsgsStateReq
"""

class MsgsStateReq_type:
    _constructors = dict()

msgs_state_req_c = BareType(name='msgs_state_req_c', number=0xda69fb52,
    params=['msg_ids'],
    param_types=[Vector(long_c)],
    result_type=MsgsStateReq_type)

MsgsStateReq = BoxedType.new('MsgsStateReq', MsgsStateReq_type)

"""
msgs_state_info#04deb57d req_msg_id:long info:bytes = MsgsStateInfo
"""

class MsgsStateInfo_type:
    _constructors = dict()

msgs_state_info_c = BareType(name='msgs_state_info_c', number=0x04deb57d,
    params=['req_msg_id', 'info'],
    param_types=[long_c, bytes_c],
    result_type=MsgsStateInfo_type)

MsgsStateInfo = BoxedType.new('MsgsStateInfo', MsgsStateInfo_type)

"""
msgs_all_info#8cc0d131 msg_ids:Vector<long> info:bytes = MsgsAllInfo
"""

class MsgsAllInfo_type:
    _constructors = dict()

msgs_all_info_c = BareType(name='msgs_all_info_c', number=0x8cc0d131,
    params=['msg_ids', 'info'],
    param_types=[Vector(long_c), bytes_c],
    result_type=MsgsAllInfo_type)

MsgsAllInfo = BoxedType.new('MsgsAllInfo', MsgsAllInfo_type)

"""
msg_detailed_info#276d3ec6 msg_id:long answer_msg_id:long bytes:int status:int = MsgDetailedInfo
"""

class MsgDetailedInfo_type:
    _constructors = dict()

msg_detailed_info_c = BareType(name='msg_detailed_info_c', number=0x276d3ec6,
    params=['msg_id', 'answer_msg_id', 'bytes', 'status'],
    param_types=[long_c, long_c, int_c, int_c],
    result_type=MsgDetailedInfo_type)

MsgDetailedInfo = BoxedType.new('MsgDetailedInfo', MsgDetailedInfo_type)
