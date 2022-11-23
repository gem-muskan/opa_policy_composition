# opa_policy_composition

Idea behind this  Each team writes their policy in a separate package, then you write one more policy(main) 
that imports all the teams policies and makes a decision

We can write main policy in many ways:
main : as per input (http.path) we will identify which policy to call
       'opa eval -f pretty -d . 'data.main.decision' --input input.json'

main2 : we only want result of particular policy
        'opa eval -f pretty -d . 'data.main2.allow_<policy_name>' --input input.json'
