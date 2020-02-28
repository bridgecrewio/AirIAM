resource "aws_iam_group" "admins_group" {
  name = "admins"
}

resource "aws_iam_group_policy_attachment" "admin_policy_attachment" {
  group      = aws_iam_group.admins_group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_group_membership" "admin_users" {
  group = aws_iam_group.admins_group.name
  name  = "admin-group-membership"
  users = local.admin_users
}
