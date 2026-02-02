$k = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($k)
[IO.File]::WriteAllBytes("mylib_aeskey.bin",$k)
