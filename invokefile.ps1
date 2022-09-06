#Script to download from url
$uri = Read-Host("Enter file URL: ")
$filenamearr = $uri.Split("/")
$filename = $filenamearr[$filenamearr.Length-1]
$savepath = "C:\users\$env:UserName\Downloads\$filename"
if($filename.Length -gt 0){
    Write-Host("Download of $filename begins")
    Invoke-WebRequest -Uri $uri -OutFile $savepath
    Read-Host("File downloaded. Press key to exit...")
}else{Write-Host("Filename not valid")
    Write-Host("Press key to exit...")
}
