# Test Cases

| Test ID | Scenario | Input | Expected Result |
|---|---|---|---|
| TC-01 | Valid IP address | 8.8.8.8 | Risk result displayed |
| TC-02 | Invalid IP format | 999.999.999.999 | Error message shown |
| TC-03 | Empty input | "" | Validation warning |
| TC-04 | Suspicious domain | malicious-example.com | High-risk warning |
| TC-05 | Random text input | hello123 | Invalid input message |
| TC-06 | Invalid IP-like input | 999.999.999.999 | Validation error shown | PASS |
| TC-07 | Invalid IP-like input with letters | 999.999.999.99a | Validation error shown | PASS |
| TC-09 | Random unknown domain | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com | Unknown / insufficient data | LOW risk | FAIL | Before fix |
| TC-09 | Random unknown domain | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com | Unknown / insufficient data | Unknown / insufficient data | PASS | After Fix |
