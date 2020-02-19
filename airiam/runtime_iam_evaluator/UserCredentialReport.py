class UserCredentialReport:
    def __init__(self, user, arn, user_creation_time, password_enabled, password_last_used, password_last_changed, password_next_rotation, mfa_active,
                 access_key_1_active, access_key_1_last_rotated, access_key_1_last_used_date, access_key_1_last_used_region,
                 access_key_1_last_used_service, access_key_2_active, access_key_2_last_rotated, access_key_2_last_used_date,
                 access_key_2_last_used_region, access_key_2_last_used_service, cert_1_active, cert_1_last_rotated, cert_2_active, cert_2_last_rotated):
        self.user = user
        self.arn = arn
        self.user_creation_time = user_creation_time
        self.password_enabled = password_enabled
        self.password_last_used = password_last_used
        self.password_last_changed = password_last_changed
        self.password_next_rotation = password_next_rotation
        self.mfa_active = mfa_active
        self.access_key_1_active = access_key_1_active
        self.access_key_1_last_rotated = access_key_1_last_rotated
        self.access_key_1_last_used_date = access_key_1_last_used_date
        self.access_key_1_last_used_region = access_key_1_last_used_region
        self.access_key_1_last_used_service = access_key_1_last_used_service
        self.access_key_2_active = access_key_2_active
        self.access_key_2_last_rotated = access_key_2_last_rotated
        self.access_key_2_last_used_date = access_key_2_last_used_date
        self.access_key_2_last_used_region = access_key_2_last_used_region
        self.access_key_2_last_used_service = access_key_2_last_used_service
        self.cert_1_active = cert_1_active
        self.cert_1_last_rotated = cert_1_last_rotated
        self.cert_2_active = cert_2_active
        self.cert_2_last_rotated = cert_2_last_rotated
