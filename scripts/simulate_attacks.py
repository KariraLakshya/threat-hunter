"""
simulate_attacks.py — Direct Boto3 script to generate real CloudTrail logs
for the AWS techniques we map in mitre_mapper.py.

This bypasses the broken Pacu framework entirely while achieving the exact same result:
real API calls that CloudTrail records for our RAG index.

Techniques triggered safely:
  - T1526 (Discovery): ListUsers, ListRoles
  - T1530 (Collection): ListBuckets, GetBucketAcl
  - T1562.008 (Evade): DescribeTrails, GetTrailStatus
"""

import boto3
import logging
import os
from botocore.exceptions import ClientError
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("attack_simulator")

def trigger_t1526_discovery():
    log.info("Triggering T1526 (Cloud Service Discovery)...")
    iam = boto3.client("iam")
    
    try:
        # These are exactly what Pacu's iam__enum runs
        iam.list_users(MaxItems=5)
        log.info("  ✓ iam:ListUsers generated")
        iam.list_roles(MaxItems=5)
        log.info("  ✓ iam:ListRoles generated")
        iam.get_account_summary()
        log.info("  ✓ iam:GetAccountSummary generated")
    except ClientError as e:
        log.warning(f"  Expected error/permission denied (still logged in CloudTrail): {e}")

def trigger_t1530_collection():
    log.info("\nTriggering T1530 (Data from Cloud Storage)...")
    s3 = boto3.client("s3")
    
    try:
        response = s3.list_buckets()
        log.info("  ✓ s3:ListBuckets generated")
        
        # Pick the first bucket and try to read it to simulate enumeration
        buckets = response.get("Buckets", [])
        if buckets:
            target = buckets[0]["Name"]
            log.info(f"  Targeting bucket: {target}")
            s3.get_bucket_acl(Bucket=target)
            log.info("  ✓ s3:GetBucketAcl generated")
            s3.get_bucket_policy_status(Bucket=target)
            log.info("  ✓ s3:GetBucketPolicyStatus generated")
    except ClientError as e:
        log.warning(f"  Expected error (still logged): {e}")

def trigger_t1562_evasion():
    log.info("\nTriggering T1562.008 (Disable Cloud Logs)...")
    cloudtrail = boto3.client("cloudtrail")
    
    try:
        response = cloudtrail.describe_trails()
        log.info("  ✓ cloudtrail:DescribeTrails generated")
        
        trails = response.get("trailList", [])
        if trails:
            target = trails[0]["Name"]
            log.info(f"  Targeting trail: {target}")
            cloudtrail.get_trail_status(Name=target)
            log.info("  ✓ cloudtrail:GetTrailStatus generated")
            
            # Simulated destructive act - we don't actually delete it, 
            # but failing to delete it leaves a great log
            try:
                cloudtrail.stop_logging(Name="fake-trail-name-for-logging")
            except ClientError:
                log.info("  ✓ cloudtrail:StopLogging (failed attempt) generated")
    except ClientError as e:
        log.warning(f"  Expected error: {e}")

def trigger_t1078_004_valid_accounts():
    log.info("\nTriggering T1078.004 (Valid Accounts: Cloud Accounts)...")
    sts = boto3.client("sts")
    try:
        sts.get_caller_identity()
        log.info("  ✓ sts:GetCallerIdentity generated (simulates account login verification)")
    except ClientError as e:
        log.warning(f"  Expected error: {e}")

def trigger_t1098_001_persistence():
    log.info("\nTriggering T1098.001 (Account Manipulation: Additional Cloud Credentials)...")
    iam = boto3.client("iam")
    try:
        # We don't want to actually create a working backdoor for safety,
        # so we try to create a key for a non-existent user.
        # It fails, but CloudTrail still records the CreateAccessKey intent.
        iam.create_access_key(UserName="fake-backdoor-user-for-logging")
    except ClientError as e:
        log.info(f"  ✓ iam:CreateAccessKey (failed attempt) generated")

def trigger_t1496_impact():
    log.info("\nTriggering T1496 (Resource Hijacking / Cryptomining)...")
    ec2 = boto3.client("ec2")
    try:
        # Try to launch a massive GPU instance (p3.16xlarge)
        # We use DryRun=True so we don't actually launch/pay for it,
        # but CloudTrail still logs the RunInstances request.
        ec2.run_instances(
            ImageId="ami-0c55b159cbfafe1f0", # random Amazon Linux 2 AMI
            InstanceType="p3.16xlarge",
            MinCount=1, MaxCount=1,
            DryRun=True
        )
    except ClientError as e:
        log.info("  ✓ ec2:RunInstances (DryRun attempt) generated")

if __name__ == "__main__":
    log.info("=== CloudTrail Event Generator (Bypassing Pacu) ===\n")
    trigger_t1526_discovery()
    trigger_t1530_collection()
    trigger_t1562_evasion()
    trigger_t1078_004_valid_accounts()
    trigger_t1098_001_persistence()
    trigger_t1496_impact()
    
    log.info("\nGeneration Complete.")
    log.info("These API calls are now traveling to your CloudTrail S3 bucket.")
    log.info("Wait ~3-5 minutes, then the aws_collector.py will pull them into Elasticsearch.")
    log.info("Then run: python scripts/save_scenario.py <TechniqueID>")
