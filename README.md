# Comparison of OSCORE-NG with Requests for Comments (RFCs)

| Feature                                | IPsec              | DTLS               | OSCORE             | OSCORE-NG          |
| :---                                   | :---:              | :---:              | :---:              | :---:              |
| Authenticated encryption               | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Sequential freshness                   | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| True end-to-end security               | :x:                | :x:                | :white_check_mark: | :white_check_mark: |
| Resistance to mismatch attacks         | :white_circle:*    | :white_circle:*    | :white_check_mark: | :white_check_mark: |
| Resilience to delay attacks            | :white_circle:*    | :white_circle:*    | :white_circle:*    | :white_check_mark: |
| Resistance to denial-of-sleep attacks  | :white_check_mark: | :white_check_mark: | :x:                | :white_check_mark: |

\* RFC 9175 mitigates at the cost of communication overhead

# Further Reading

- [Paper](https://dx.doi.org/10.14722/sdiotsec.2024.23003)
