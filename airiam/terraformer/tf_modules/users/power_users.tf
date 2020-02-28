resource "aws_iam_group" "power_users_group" {
  name = "powerusers"
}

resource "aws_iam_group_policy_attachment" "on_call_attachment" {
  count      = length(local.power_users_policy_arns)
  group      = aws_iam_group.power_users_group.name
  policy_arn = local.power_users_policy_arns[count.index]
}

resource "aws_iam_group_membership" "on_call_membership" {
  group = aws_iam_group.power_users_group.name
  name  = "on_call_membership"
  users = local.power_users
}