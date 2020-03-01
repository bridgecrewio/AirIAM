locals {
  chunked_policy_list = chunklist(local.power_users_policy_arns, 10)
}

resource "aws_iam_group" "power_users_groups" {
  count = length(local.chunked_policy_list)
  name  = "powerusers_${count.index}"
}

resource "aws_iam_group_policy_attachment" "on_call_attachment" {
  count      = length(local.power_users_policy_arns)
  group      = aws_iam_group.power_users_groups[floor(count.index / 10)].name
  policy_arn = local.power_users_policy_arns[count.index]
}

resource "aws_iam_group_membership" "on_call_membership" {
  count = length(local.chunked_policy_list)
  group = aws_iam_group.power_users_groups[count.index].name
  name  = "on_call_membership"
  users = local.power_users
}