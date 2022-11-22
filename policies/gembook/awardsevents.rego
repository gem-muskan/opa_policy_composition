package policies.gembook.awardsandevents

import future.keywords.if
import future.keywords
import input.attributes.request.http


default allow := false
default token := "test"

allow if {
is_token_valid
action_allowed
is_awards_and_events
}

status_code := 200 if {
allow
is_token_valid
} else = 403 {
not is_token_valid
} else = 403

body := "Action Allowed" if status_code = 200
body := "Authentication Failed" if status_code = 401
body := "Unauthorized Request" if status_code = 403

result["allowed"] := allow
result["http_status"] := status_code
result["body"] := body

token := split(http.headers.authorization," ")[1]


token_verify := io.jwt.verify_rs256(token
,
`{"kty":"RSA","e":"AQAB","use":"enc","kid":"87bca898-43fd-4c27-af2b-68f1e9c7f995","n":"1mO6qx2VGYmLHxeC8MAgi63x9Q7afGTkbEv_IcDPvsGAzDOcCJJMmHlA1HNM_mvJOIcoTSVHUQ0OiPGJzmDcYtSGiSD-JvrExBimQrUZFNN6Lzzwl_dR_DBjWKzaYW2ENOUC2rlc5iyA6zLWC_3FY5-M3CR9MKldh047VsZApRThb05BC1mVzw5fknZ75prRMlmOKTwhRbzQ6MA3yEHfaxUlZvLE5RwSeq7URd8ZABLqZ9QYi9kte3gdiTP9jWiTVLraOr_PMoK-9SqyeWHVF5fwb0FKbd66VuKkiDt0Hj2KrX4ILmRx6lDm6OyE5Mf6qiiP31l1AFuPDl0UGNUmIQ"}`)
payload := io.jwt.decode(token)[1]
is_token_valid if {
token_verify
now := time.now_ns() / 1000000000
now < payload.exp
}

action_allowed if {
http.method == "GET"
}{
http.method == "POST"
contains(payload.security_group, "HR_GROUP")
}{
http.method == "PUT"
contains(payload.security_group, "HR_GROUP")
}{
http.method == "DELETE"
contains(payload.security_group, "HR_GROUP")
}

is_awards_and_events if {
contains(http.path, "/awardsandevents")
}

