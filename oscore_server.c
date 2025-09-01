#include <coap3/coap.h>
#include <stdio.h>
#include <string.h>
static void
hnd_get(coap_resource_t *resource, coap_session_t *session,
        const coap_pdu_t *request, const coap_string_t *query,
        coap_pdu_t *response) {
    // 요청에서 payload 추출 및 출력
    size_t size;
    const uint8_t *data;
    printf("[SERVER] Received payload: ");
    if (coap_get_data(request, &size, &data) ) {
        printf("[SERVER] Received payload: ");
        fwrite(data, 1, size, stdout);
        printf("\n");
    } else {
        printf("[SERVER] No payload received in request.\n");
    }

    // 예시 응답
    const char* reply = "Hello, OSCORE!";
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data(response, strlen(reply), (const uint8_t*)reply);
}

int main(void) {
    coap_startup();
    coap_set_log_level(COAP_LOG_OSCORE);


    coap_context_t *ctx = coap_new_context(NULL);
    if (!ctx) return -1;

    // OSCORE context 구성은 라이브러리 내부에서 custom option에 따라 처리
    // (coap_dispatch에서 custom option 체크)

    // 리소스 생성
    coap_resource_t *r = coap_resource_init(coap_make_str_const("oscore"), 0);
    coap_register_handler(r, COAP_REQUEST_GET, hnd_get);
    coap_add_resource(ctx, r);

    // UDP endpoint 생성
    coap_address_t listen_addr;
    coap_address_init(&listen_addr);
    listen_addr.addr.sin.sin_family = AF_INET;
    listen_addr.addr.sin.sin_port = htons(5683);
    listen_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;
    coap_new_endpoint(ctx, &listen_addr, COAP_PROTO_UDP);

    // 이벤트 루프
    while (1) {
        coap_io_process(ctx, COAP_IO_WAIT);
    }

    coap_cleanup();
    return 0;
}