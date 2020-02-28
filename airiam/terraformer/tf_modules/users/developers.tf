resource "aws_iam_group" "developers_group" {
  name = "hippo-developers"
}

resource "aws_iam_group_policy_attachment" "developers_read_only" {
  group      = aws_iam_group.developers_group.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_group_policy_attachment" "developers_sns_sqs" {
  group      = aws_iam_group.developers_group.name
  policy_arn = "arn:aws:iam::079818613942:policy/Hippo-SQS-SNS-Developer-Readonly"
}

resource "aws_iam_group_policy_attachment" "self_credentials_attachment" {
  group      = aws_iam_group.developers_group.name
  policy_arn = aws_iam_policy.manage_self_credentials.arn
}

resource "aws_iam_group_membership" "developer_membership" {
  group = aws_iam_group.developers_group.name
  name  = "developer_membership"
  users = local.developer_users
}

data "aws_iam_policy_document" "manage_own_permissions_policy_doc" {
  statement {
    sid    = "AllowViewAccountInfo"
    effect = "Allow"
    actions = [
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowManageOwnPasswords"
    effect = "Allow"
    actions = [
      "iam:ChangePassword",
      "iam:GetUser"
    ]
    resources = ["arn:aws:iam::*:user/$\u0024{aws:username}"]
  }

  statement {
    sid    = "AllowManageOwnAccessKeys"
    effect = "Allow"
    actions = [
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey"
    ]
    resources = ["arn:aws:iam::*:user/$\u0024{aws:username}"]
  }

  statement {
    sid    = "AllowManageOwnSSHPublicKeys"
    effect = "Allow"
    actions = [
      "iam:DeleteSSHPublicKey",
      "iam:GetSSHPublicKey",
      "iam:ListSSHPublicKeys",
      "iam:UpdateSSHPublicKey",
      "iam:UploadSSHPublicKey"
    ]
    resources = ["arn:aws:iam::*:user/$\u0024{aws:username}"]
  }
}

resource "aws_iam_policy" "manage_self_credentials" {
  name   = "SelfManageUserCredentials"
  policy = data.aws_iam_policy_document.manage_own_permissions_policy_doc.json
}
