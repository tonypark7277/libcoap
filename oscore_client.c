#include <coap3/coap.h>
#include <string.h>
#include <arpa/inet.h>

#define COAP_OPTION_CUSTOM_EXPERIMENT 42122

int main(void) {
    coap_startup();
    // coap_set_log_level(COAP_LOG_OSCORE);

    // 1. 서버 주소 설정
    coap_address_t dst_addr;
    coap_address_init(&dst_addr);
    dst_addr.addr.sin.sin_family = AF_INET;
    dst_addr.addr.sin.sin_port = htons(5683);
    inet_pton(AF_INET, "127.0.0.1", &dst_addr.addr.sin.sin_addr);

    // 2. CoAP 컨텍스트 생성
    coap_context_t *ctx = coap_new_context(NULL);
    if (!ctx) return -1;

    // 3. OSCORE security context 직접 생성 및 등록
    // (서버와 동일하게 맞춰야 함!)

    static const char config_string[] =
    "master_secret,hex,000102030405060708090A0B0C0D0E0F\n"
    "sender_id,hex,0B\n"
    "recipient_id,hex,0A\n"
    "rfc8613_b_1_2,bool,false\n"
    "rfc8613_b_2,bool,false\n";

    // uint8_t master_secret[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    // uint8_t sender_id[]     = { 0x02 }; // client가 sender!
    // uint8_t recipient_id[]  = { 0x01 };
    // uint8_t master_salt[]   = { 0xA0, 0xA1 };

    // coap_bin_const_t ms = { .length = sizeof(master_secret), .s = master_secret };
    // coap_bin_const_t sid = { .length = sizeof(sender_id), .s = sender_id };
    // coap_bin_const_t rid = { .length = sizeof(recipient_id), .s = recipient_id };
    // coap_bin_const_t salt = { .length = sizeof(master_salt), .s = master_salt };

    // coap_oscore_conf_t oscore_conf;
    // memset(&oscore_conf, 0, sizeof(oscore_conf));
    // oscore_conf.master_secret = &ms;
    // oscore_conf.sender_id = &sid;
    // oscore_conf.recipient_id = &rid;
    // oscore_conf.master_salt = &salt;
    // // 필요시 alg 등 추가 세팅

    // OSCORE client context 생성 및 등록

     coap_oscore_conf_t *config_structure =
        coap_new_oscore_conf(*coap_make_str_const(config_string),
                             NULL,
                             NULL,
                             0);
    // coap_context_oscore_client(ctx, config_structure);

    // 4. 세션 생성
    coap_session_t *session = coap_new_client_session_oscore(ctx, NULL, &dst_addr, COAP_PROTO_UDP, config_structure);

    // 5. 요청 PDU 생성
    coap_pdu_t *pdu = coap_pdu_init(COAP_MESSAGE_CON, COAP_REQUEST_GET,
                                    coap_new_message_id(session), coap_session_max_pdu_size(session));
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 6, (const uint8_t*)"oscore");

    // 6. 커스텀 옵션 값 추가 (실험)
    uint8_t val = 0x01;
    coap_add_option(pdu, COAP_OPTION_CUSTOM_EXPERIMENT, 1, &val);

    // 7. 전송
    coap_send(session, pdu);

    // 8. 응답 처리 (1초 대기 후 종료)
    coap_run_once(ctx, 1000);

    coap_cleanup();
    return 0;
}