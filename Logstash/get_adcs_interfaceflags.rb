def register(params)
  @fields = params['field']
  @fields = [@fields] unless @fields.is_a?(Array)
end

def filter(event)
  const = {
    'IF_LOCKICERTREQUEST' => 0x00000001,
    'IF_NOREMOTEICERTREQUEST' => 0x00000002,
    'IF_NOLOCALICERTREQUEST' => 0x00000004,
    'IF_NORPCICERTREQUEST' => 0x00000008,
    'IF_NOREMOTEICERTADMIN' => 0x00000010,
    'IF_NOLOCALICERTADMIN' => 0x00000020,
    'IF_NOREMOTEICERTADMINBACKUP' => 0x00000040,
    'IF_NOLOCALICERTADMINBACKUP' => 0x00000080,
    'IF_NOSNAPSHOTBACKUP' => 0x00000100,
    'IF_ENFORCEENCRYPTICERTREQUEST' => 0x00000200,
    'IF_ENFORCEENCRYPTICERTADMIN' => 0x00000400,
    'IF_ENABLEEXITKEYRETRIEVAL' => 0x00000800,
    'IF_ENABLEADMINASAUDITOR' => 0x00001000
  }

  @fields.each do |field|
    value = event.get(field)
    next if value.nil?

    flags_list = []
    const.each_pair do |key, bitmask|
      if value.to_i & bitmask != 0
        flags_list << key
      end
    end

    event.set(field, flags_list)
  end

  return [event]
end


# run tests:
# logstash -e "filter { ruby { path => '/usr/share/logstash/scripts/get_adcs_interfaceflags.rb' } }" -t

test "parse with test_field '1601' (0x641)" do
  parameters do
    { "field" => "test_field" }
  end

  in_event { { "test_field" => "1601" } }

  expect("check that test_field has required policy flags") do |events|
    events.first.get("test_field") == ["IF_LOCKICERTREQUEST", "IF_NOREMOTEICERTADMINBACKUP", "IF_ENFORCEENCRYPTICERTREQUEST", "IF_ENFORCEENCRYPTICERTADMIN"]
  end
end

test "parse with test_field '514' (0x202)" do
  parameters do
    { "field" => "test_field" }
  end

  in_event { { "test_field" => "514" } }

  expect("check that test_field has required policy flags") do |events|
    events.first.get("test_field") == ["IF_NOREMOTEICERTREQUEST", "IF_ENFORCEENCRYPTICERTREQUEST"]
  end
end

test "parse with multiple fields ['f1', 'f2']" do
  parameters do
    { "field" => ["f1", "f2"] }
  end

  in_event { { "f1" => "1601", "f2" => "514" } }

  expect("check that both f1 and f2 have required policy flags") do |events|
    e = events.first
    e.get("f1") == ["IF_LOCKICERTREQUEST", "IF_NOREMOTEICERTADMINBACKUP", "IF_ENFORCEENCRYPTICERTREQUEST", "IF_ENFORCEENCRYPTICERTADMIN"] &&
    e.get("f2") == ["IF_NOREMOTEICERTREQUEST", "IF_ENFORCEENCRYPTICERTREQUEST"]
  end
end