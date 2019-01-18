# boto3-cloudformation
Perform operation on a CFT like Create,update,Delete Stacks

Takes a parmater file(refere sample here) as input and performs operations like create,update and deletion of stacks based on the current stack status.

Below properties are mandatory in paramater file. Tags are optional and remaining properties are passed as Template properties if given as key value pair.

"RegionId"\n
"TemplateUrl"\n
"StackName"
 

Sample Execution :

python3 cft_operations.py -p parameters.json -r {role-to-assume}
