package main2

import data.policies.mis.employeedirectory
import data.policies.gembook.awardsandevents
import data.baeldung.auth.account2


allow_employeedirectory := employeedirectory.result
allow_awardsevents := awardsandevents.result

##
allow_account2 := account2.access
