##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit
    include Msf::Exploit::Remote::Telnet

    def initialize
      super(
          'Name'            => %q(Dahua Telnet Login),
          'Description'     => %q(Utilizing the '888888' login to obtain Telnet session.),
          'Author'          => [
              'Terry Antram - 3antrt67[at]solent.ac.uk'
          ],
          'License'         => MSF_LICENSE
      )

      deregister_options('RHOST')
      register_options(
          [
              Opt::RPORT(23),
          ])
    end

    def run
        connect
        if not connect
            print_error("Issue with connection")
        return
    end
end
