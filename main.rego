package main

import input.attributes.request.http

default result = false
default msg = "No applicable policy found"

applicable_policy := {
    "awardsevents": "gembook",
    "notification": "gembook",
    "employeedirectory": "mis",
    "referral": "mis",
}

name := split(http.path,"/")
policy:= name[1]
product := applicable_policy[policy]


router = data.policies[product][policy].result


result {
  router["allowed"]
}
msg = router["body"]


decision["allow"] =  result
decision["reason"] = msg
decision["explain"] = router["http_status"]


