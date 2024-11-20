import streamlit as st
import boto3
import botocore.exceptions
import json
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage,SystemMessage

load_dotenv()

if "s3_client" not in st.session_state:
    st.session_state.s3_client = boto3.client('s3')
if "group_client" not in st.session_state:
    st.session_state.group_client = boto3.client('iam')

@tool
def get_bucket_files(bucket_name:str) -> dict:
    """Returns the names of files present in bucket if it exists.

    Args:
        bucket_name: str
    """
    items_in_bucket = []
    try:
        buckets = [i['Name'] for i in st.session_state.s3_client.list_buckets()['Buckets']]
        arn = r'arn:aws:s3:::' + bucket_name
        if bucket_name in buckets:
            items_in_bucket = [item.get('Key','') for item in st.session_state.s3_client.list_objects_v2(Bucket=bucket_name).get('Contents',[])]
    except Exception as e:
        print(e,'Getting bucket files')
    finally:
        return {"files":items_in_bucket}

@tool
def get_user_group_policy(bucket_name:str) -> dict:
    """Returns the user group policy if defined for the bucket.

    Args:
        bucket_name: str
    """
    buckets = [i['Name'] for i in st.session_state.s3_client.list_buckets()['Buckets']]
    arn = r'arn:aws:s3:::' + bucket_name

    if bucket_name not in buckets:
        return {'error':'No such bucket found'}
    
    arn = r'arn:aws:s3:::' + bucket_name
    for group in st.session_state.group_client.list_groups()['Groups']:
        for policy in st.session_state.group_client.list_attached_group_policies(GroupName=group['GroupName'])['AttachedPolicies']:
            policy_arn = st.session_state.group_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['Arn']
            version_id = st.session_state.group_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
            policies = st.session_state.group_client.get_policy_version(PolicyArn=policy_arn,VersionId=version_id)['PolicyVersion']['Document']['Statement']
            for policy_text in policies:
                if type(policy_text['Resource']) == list and arn in policy_text['Resource']:
                    return {"policy":policy_text}
                elif type(policy_text['Resource']) == str and arn == policy_text['Resource']:
                    return {"policy":policy_text}
    return {'error':'No user group configured policy for bucket'}

@tool
def get_bucket_policy(bucket_name:str):
    """Returns the bucket policy if defined for the bucket.

    Args:
        bucket_name: str
    """

    buckets = [i['Name'] for i in st.session_state.s3_client.list_buckets()['Buckets']]
    arn = r'arn:aws:s3:::' + bucket_name

    if bucket_name not in buckets:
        return {'error':'No such bucket found'}
    
    try:
        policy = json.loads(st.session_state.s3_client.get_bucket_policy(Bucket=bucket_name)['Policy'])

        return {"policy":policy['Statement']}
    except botocore.exceptions.ClientError:
        return {"error":"Check user group policy for configuration"}

if "llm_with_tools" not in st.session_state:

    st.session_state.llm = ChatOpenAI(model="gpt-4o")
    st.session_state.tools = [get_bucket_files,get_bucket_policy,get_user_group_policy]
    st.session_state.llm_with_tools = st.session_state.llm.bind_tools(st.session_state.tools)

prompt = r""" 

    You are a cloud security assistant that will analyze S3 bucket configurations to identify risks, assess exposure, and provide prioritized mitigation recommendations. Invoke tools with bucket names provided by the user. In case the user does not provide bucket names , prompt him to provide the bucket name to get tailored recommendations.

    # Steps

    1. **Identify Bucket Configuration requested by the user**: 
    Analyze details such as:
    - Bucket access level (Public or Private)
    - Permission type (Read-Only, Write-Access, or Both)
    - Whether the bucket has sensitive files in it.

    2. **Evaluate Risks Based on Configuration**:
    Assess and identify associated risks:
    - **Public Access**: Identify if unauthorized access or data leakage risk exists.
    - **Permissions**: Determine potential risks of unauthorized data modification or uploads. 
    - **Static Web Hosting**: Check for vulnerabilities related to static websites, such as unintended directory listings or content manipulation.
    - **Sensitive Data Exposure**: Identify if personally identifiable information (PII) or confidential data is publicly accessible.

    3. **Prioritize the Security Issues**:
    Determine the priority of each identified issue based on:
    - **Exposure Level**: How visible or open data is to unauthorized entities.
    - **Sensitivity of Data**: Assess the type of data (e.g., sensitive information like PII) in terms of its criticality if exposed.
    - **Potential Impact & Likelihood of Exploitation**: Evaluate the impact if the data is compromised or altered, and the likelihood of this risk occurring.
    - **Ease of Mitigation**: Consider how feasible it is to mitigate the issue.

    # Output Format

    Provide a list of security issues, each including its category, associated risk, priority level, and suggested recommendations. Use the following structure:

    ** Bucket Name ** : [bucket_name]

    ## Issues Identified
    [issues list]

    ** Priority ** : [Critical/High/Medium/Low]

    ## Risk Description
    [description_of_risk]

    ## Recommendations
    [recommendation to mitigate the issue]
    [additional recommendations if applicable]

    # Examples

    **Input**: 
    I have a public S3 bucket named [bucket_name]. Can you check if there is a security risk? What types of risks might exist, and what should be the priorities?

    **Example Output**:

    ** Bucket Name ** : [bucket_name]

    ## Issues Identified
    1. Public Write Access Provided

    ** Priority ** : Critical

    ## Risk Description
    Anyone can write data to this bucket , which is not safe.

    ## Recommendations
    Remove public write access and instead used group based access to enable writes to buckets

    # Notes

    - For public buckets containing sensitive data, prioritize the risk as "Critical."
    - Static website capability should generally be disabled for buckets containing PII or sensitive data.
    - Always list multiple recommendations if there are feasible mitigation options.
    - If data sensitivity is non-existent, risks may be lowered to Medium or Low based on exposure and permissions.

    """

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = [{"role":"system","content":SystemMessage(prompt)}]
    st.session_state.issues = []
    with st.sidebar:
        st.markdown("# Issues")
st.title("AWS S3 Bot")

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    try:
        role = message["role"]
        content = message["content"].content
        if role != 'system':
            with st.chat_message(role):
                st.markdown(content)
    except Exception as e:
        print(e)

# React to user input
if prompt := st.chat_input("Please enter your query !"):
    # Display user message in chat message container
    st.chat_message("user").markdown(prompt)
    # Add user message to chat history
    st.session_state.messages.append({"role":"human","content":HumanMessage(prompt)})

    so_far = []
    for data in st.session_state.messages:
        so_far.append(data["content"])

    ai_msg = st.session_state.llm_with_tools.invoke(so_far)
    so_far.append(ai_msg)
    st.session_state.messages.append({"role":"ai","content":ai_msg})
    for tool_call in ai_msg.tool_calls:
        selected_tool = {"get_bucket_files": get_bucket_files,"get_bucket_policy":get_bucket_policy,"get_user_group_policy":get_user_group_policy}[tool_call["name"].lower()]
        tool_msg = selected_tool.invoke(tool_call)
        so_far.append(tool_msg)
        st.session_state.messages.append({"role":"tool","content":tool_msg})

    response = st.session_state.llm_with_tools.invoke(so_far)
    try:
        issues = response.content.split("\n\n")[1]
        with st.sidebar:
            st.markdown("# Issues")
            st.markdown(issues)
    except IndexError:
        pass

    # Display assistant response in chat message container
    with st.chat_message("assistant"):
        st.markdown('\n'+response.content.strip())

    # Add assistant response to chat history
    so_far.append(response)
    st.session_state.messages.append({"role":"ai","content":response})