from airiam.models.RuntimeReport import RuntimeReport
from airiam.recommend_groups.RoleOrganizer import RoleOrganizer
from airiam.recommend_groups.UserOrganizer import UserOrganizer


def recommend_groups(logger, runtime_iam_report: RuntimeReport, unused_threshold=90):
    account_id = runtime_iam_report.get_raw_data()['AccountRoles'][0]['Arn'].split(":")[4]
    logger.info("Analyzing data for account {}".format(account_id))

    users_reorg = UserOrganizer(logger, unused_threshold).get_user_clusters(runtime_iam_report.get_raw_data())
    roles_reorg = RoleOrganizer(logger, unused_threshold).rightsize_privileges(runtime_iam_report.get_raw_data())

    return runtime_iam_report.set_reorg(users_reorg, roles_reorg)
