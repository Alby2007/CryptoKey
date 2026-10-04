param([string]$cmd)
$p = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'cryptokey-ctl', [System.IO.Pipes.PipeDirection]::InOut)
$p.Connect(1500)
$w = New-Object System.IO.StreamWriter($p); $w.AutoFlush = $true
$w.WriteLine($cmd)
Write-Output (New-Object System.IO.StreamReader($p)).ReadLine()
$p.Dispose()
