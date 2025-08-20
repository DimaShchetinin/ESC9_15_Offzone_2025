def register(params)
  @field = params['field']
end

def filter(event)
  const = {
    'CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS' => 0x00000001,
    'CT_FLAG_PEND_ALL_REQUESTS' => 0x00000002,
    'CT_FLAG_PUBLISH_TO_KRA_CONTAINER' => 0x00000004,
    'CT_FLAG_PUBLISH_TO_DS' => 0x00000008,
    'CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE' => 0x00000010,
    'CT_FLAG_AUTO_ENROLLMENT' => 0x00000020,
    'CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT' => 0x00000040,
    'CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED' => 0x00000080,
    'CT_FLAG_USER_INTERACTION_REQUIRED' => 0x00000100,
    'CT_FLAG_ADD_TEMPLATE_NAME' => 0x00000200,
    'CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE' => 0x00000400,
    'CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF' => 0x00000800,
    'CT_FLAG_ADD_OCSP_NOCHECK' => 0x00001000,
    'CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL' => 0x00002000,
    'CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS' => 0x00004000,
    'CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS' => 0x00008000,
    'CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT' => 0x00010000,
    'CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST' => 0x00020000,
    'CT_FLAG_SKIP_AUTO_RENEWAL' => 0x00040000,
    'CT_FLAG_NO_SECURITY_EXTENSION' => 0x80000
  }
  flags_list = []
  flags =  event.get(@field)
  const.each_pair do |key, value|
    if flags.to_i() & value != 0
      flags_list << key
    end
  end
  event.set(@field, flags_list)
  return [event]
end
  
# run tests:
# logstash -e "filter { ruby { path => '/usr/share/logstash/scripts/get_pki_enrollment_flags.rb' } }" -t

test "parse with test_field '41' " do
  parameters do
    { "field" => "test_field" }
  end
  in_event { { "test_field" => "41" } }

  expect("check that test_field has required flags") do |events|
    events.first.get("test_field") == ["CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS", "CT_FLAG_PUBLISH_TO_DS", "CT_FLAG_AUTO_ENROLLMENT"]
  end
end

test "parse with test_field '43' " do
  parameters do
    { "field" => "test_field" }
  end
  in_event { { "test_field" => "43" } }

  expect("check that test_field has required flags") do |events|
    events.first.get("test_field") == ["CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS", "CT_FLAG_PEND_ALL_REQUESTS", "CT_FLAG_PUBLISH_TO_DS", "CT_FLAG_AUTO_ENROLLMENT"]
  end
end

test "parse with test_field '9' " do
  parameters do
    { "field" => "test_field" }
  end
  in_event { { "test_field" => "9" } }

  expect("check that @field has required flags") do |events|
    events.first.get("test_field") == ["CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS", "CT_FLAG_PUBLISH_TO_DS"]
  end
end