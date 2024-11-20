# AWS-Security-Bot
This repository combines the Gen AI functionality with AWS boto library to identify configuration errors if present and provide possible solutions to them

# Steps to run the project

1. Download all requirement libraries := `pip install -r requirements.txt`
2. Run the file with streamlit := `streamlit run submission.py`

# Requirements
1. Ensure environment values for AWS boto3 client and OpenAI client are configured `AWS_ACCESS_KEY_ID` , `AWS_SECRET_ACCESS_KEY` , `OPENAI_API_KEY`.
2. Ensure Open AI account has access for the `gpt-4o` model.
