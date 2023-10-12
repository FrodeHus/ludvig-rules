rule ConnectionStrings : connectionstring secret{
    meta:
        description = "Detects connection strings with credentials"
        severity = "HIGH"
        id = "LS0020"

    strings:
        $connection_string_sqlserver = /Data Source=.{1,100};User ID=.{1,60};Password=.{1,60};/ nocase ascii
        $connection_string_postgres = /postgres:\/\/[^:]+:[^@]+@[^:]+:\d+\/[^?]+/ nocase ascii
        $connection_string_mongodb = /mongodb:\/\/[^:]+:[^@]+@[^:]+:\d+\/[^?]+/ nocase ascii
        $connection_string_mysql = /mysql:\/\/[^:]+:[^@]+@[^:]+:\d+\/[^?]+/ nocase ascii
        $connection_string_oracle = /jdbc:oracle:thin:@[^:]+:[^\/]+\/[^?]+/ nocase ascii

    condition:
        any of them
}
