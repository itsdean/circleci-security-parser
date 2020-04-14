import argparse
import os
import boto3

from dotenv import load_dotenv
load_dotenv()

def get_client(nuk):
    print("yes")

if __name__ == "__main__":
    print("main()")

    parser = argparse.ArgumentParser()
    parser.add_argument("--nuk", action="store_true")

    args = parser.parse_args()

    if not args.nuk:
        bucket_name = os.getenv("PARSER_AWS_BUCKET_NAME")

        s3 = boto3.client(
            's3',
            aws_access_key_id=os.getenv("PARSER_AWS_AK_ID"),
            aws_secret_access_key=os.getenv("PARSER_AWS_SK")
        )
        # resource = boto3.resource(
        #     's3',
        #     aws_access_key_id=os.getenv("PARSER_AWS_AK_ID"),
        #     aws_secret_access_key=os.getenv("PARSER_AWS_SK")
        # )
    else:
        bucket_name = os.getenv("PARSER_AWS_BUCKET_NAME_NUK")

        s3 = boto3.client(
            's3',
            aws_access_key_id=os.getenv("PARSER_AWS_AK_ID_NUK"),
            aws_secret_access_key=os.getenv("PARSER_AWS_SK_NUK")
        ) 
        # resource = boto3.resource(
        #     's3',
        #     aws_access_key_id=os.getenv("PARSER_AWS_AK_ID"),
        #     aws_secret_access_key=os.getenv("PARSER_AWS_SK")
        # )
    print("bucket name: " + bucket_name)

    print("testing upload of scan output")

    import glob
    path = "test_output/"
    pattern = "*.csv"
    output_files = glob.glob(path + pattern)
    # print(output_files)

    if len(output_files) == 1:
        print("uploading file to s3")
        s3.upload_file(
            Key=output_files[0],
            Filename=output_files[0],
            Bucket=bucket_name
        )

    filename = "test_output"

    objects = s3.list_objects_v2(Bucket=bucket_name)
    from pprint import pprint
    for choices in objects["Contents"]:
        print(choices["Key"])