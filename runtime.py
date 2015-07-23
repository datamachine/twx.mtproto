TL_CONSTRUCTORS="""
resPQ#05162463 nonce:int128 server_nonce:int128 pq:bytes server_public_key_fingerprints:Vector<long> = ResPQ;

p_q_inner_data#83c95aec pq:bytes p:bytes q:bytes nonce:int128 server_nonce:int128 new_nonce:int256 = P_Q_inner_data;


server_DH_params_fail#79cb045d nonce:int128 server_nonce:int128 new_nonce_hash:int128 = Server_DH_Params;
server_DH_params_ok#d0e8075c nonce:int128 server_nonce:int128 encrypted_answer:bytes = Server_DH_Params;

server_DH_inner_data#b5890dba nonce:int128 server_nonce:int128 g:int dh_prime:bytes g_a:bytes server_time:int = Server_DH_inner_data;

client_DH_inner_data#6643b654 nonce:int128 server_nonce:int128 retry_id:long g_b:bytes = Client_DH_Inner_Data;

dh_gen_ok#3bcbf734 nonce:int128 server_nonce:int128 new_nonce_hash1:int128 = Set_client_DH_params_answer;
dh_gen_retry#46dc1fb9 nonce:int128 server_nonce:int128 new_nonce_hash2:int128 = Set_client_DH_params_answer;
dh_gen_fail#a69dae02 nonce:int128 server_nonce:int128 new_nonce_hash3:int128 = Set_client_DH_params_answer;

rpc_result#f35c6d01 req_msg_id:long result:Object = RpcResult;
rpc_error#2144ca19 error_code:int error_message:string = RpcError;

rpc_answer_unknown#5e2ad36e = RpcDropAnswer;
rpc_answer_dropped_running#cd78e586 = RpcDropAnswer;
rpc_answer_dropped#a43ad8b7 msg_id:long seq_no:int bytes:int = RpcDropAnswer;

future_salt#0949d9dc valid_since:int valid_until:int salt:long = FutureSalt;
future_salts#ae500895 req_msg_id:long now:int salts:vector<future_salt> = FutureSalts;

pong#347773c5 msg_id:long ping_id:long = Pong;

destroy_session_ok#e22045fc session_id:long = DestroySessionRes;
destroy_session_none#62d350c9 session_id:long = DestroySessionRes;

new_session_created#9ec20908 first_msg_id:long unique_id:long server_salt:long = NewSession;

msg_container#73f1f8dc messages:vector<%Message> = MessageContainer;
message msg_id:long seqno:int bytes:int body:Object = Message;
msg_copy#e06046b2 orig_message:Message = MessageCopy;

gzip_packed#3072cfa1 packed_data:bytes = Object;

msgs_ack#62d6b459 msg_ids:Vector<long> = MsgsAck;

bad_msg_notification#a7eff811 bad_msg_id:long bad_msg_seqno:int error_code:int = BadMsgNotification;
bad_server_salt#edab447b bad_msg_id:long bad_msg_seqno:int error_code:int new_server_salt:long = BadMsgNotification;

msg_resend_req#7d861a08 msg_ids:Vector<long> = MsgResendReq;
msgs_state_req#da69fb52 msg_ids:Vector<long> = MsgsStateReq;
msgs_state_info#04deb57d req_msg_id:long info:bytes = MsgsStateInfo;
msgs_all_info#8cc0d131 msg_ids:Vector<long> info:bytes = MsgsAllInfo;
msg_detailed_info#276d3ec6 msg_id:long answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
msg_new_detailed_info#809db6df answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
"""

header_template = '"""\n{header}\n"""'

bare_type_template = """\
{name} = BareType(name='{name}', number={number},
    params=[{params}],
    param_types=[{param_types}],
    result='{result_type}_type')
"""

boxed_type_template = """\
{result_type} = BoxedType.new('{result_type}', '{result_type}_type')
"""

from collections import OrderedDict, namedtuple

ConInfo = namedtuple('ConData', 'result_type header definition')

bare_types = OrderedDict()

for raw_con in TL_CONSTRUCTORS.split(';')[:-2]:
    con_iter = iter(raw_con.split())

    token = next(con_iter)
    try:
        name, number = token.split('#')
        number = '0x{}'.format(number)
    except ValueError:
        name, number = token, "crc32('{}'.encode())".format(raw_con.strip())

    name = '{}_c'.format(name)

    tl_params = []

    token = next(con_iter)
    while token != '=':
        tl_params.append(token)
        token = next(con_iter)

    result_type = next(con_iter)
    if result_type == 'Object':
        result_type = 'TLType'

    try:
        next(con_iter)
        raise SyntaxError('extra data not accounted')
    except StopIteration:
        pass

    params = []
    param_types = []
    for p in tl_params:
        assert len(p.split(':')) == 2
        param, param_type = p.split(':')
        if param_type.lower().startswith('vector'):
            vector, vector_item_type = param_type.split('<')
            vector_item_type = vector_item_type.replace('>', '')

            if vector == 'vector':
                vector = 'vector_c'

            if vector_item_type.startswith('%'):
                vector_item_type = vector_item_type.lower().replace('%', '')

            if vector_item_type.lower() == vector_item_type:
                vector_item_type = '{}_c'.format(vector_item_type)

            param_type = '{}({})'.format(vector, vector_item_type)
        elif param_type.lower() == param_type:
            param_type = '{}_c'.format(param_type)

        if param_type == 'Object':
            param_type = 'TLType'

        params.append(param)
        param_types.append(param_type)

    assert len(params) == len(param_types)

    header = raw_con.strip()

    bare_type = bare_type_template.format(
        name=name,
        number=number,
        params=', '.join([repr(p) for p in params]),
        param_types=', '.join(param_types),
        result_type=result_type
        )

    bare_types.setdefault(result_type, list()).append(ConInfo(result_type, header, bare_type))

    # print(header)
    # print(bare_type)

    # if '{}_c'.format(result_type).upper() == name.upper():
    #     boxed_type = boxed_type_template.format(boxed_name=result_type, bare_name=name)
    #     print(boxed_type)

    # print()
    # cons.setdefault(result_type, list()).append(bare_type)

for result_type, bares in bare_types.items():
    print('"""')
    for bare_type in bares:
        print(bare_type.header)
    print('"""')

    for bare_type in bares:
        print(bare_type.definition)

    print(boxed_type_template.format(result_type=result_type))

# print(cons)


# for result_type, items in cons.items():
#     for i in items:
#         print(i)

#     if result_type != 'TLType':
#         print(boxed_type_template.format(result_type))
