#Based on LegacyNSFW's XDF to IDC script. Updated to convert to Ghidra-compatible labels.

param ($SourceXdf)

$builder = New-Object -TypeName "System.Text.StringBuilder";

[xml]$xdf = Get-Content $SourceXdf

function Sanitize-Name ([string] $Name)
{
	$output = ""
	$lastChar = " "

	foreach ($c in ($Name -split ''))
	{
		if (($c -eq " ") -or ($c -eq "_") -or ($c -eq "-"))
		{
			if ($lastChar.ToString() -ne "_")
			{
				$output += "_"
			}
			$lastChar = "_"
		}
		
		if ($c -eq "")
		{
			continue
		}

		if ([System.Char]::IsLetter($c) -or [System.Char]::IsNumber($c))
		{
			$output += $c
			$lastChar = $c.ToString();
		}
	}

	return $output
}

foreach ($flag in $xdf.XDFFORMAT.XDFFLAG)
{
	$name = "Flag" + $flag.mask + $flag.title 
	$address = $flag.EMBEDDEDDATA.mmedaddress;
	$name = $name -replace '\s',''
	if ($address) {
		$unused = $builder.AppendLine("$name $address l")
	}
}

foreach ($constant in $xdf.XDFFORMAT.XDFCONSTANT)
{
	$size = $constant.EMBEDDEDDATA.mmedelementsizebits
	$name = "Constant" + $size + $constant.title 
	$address = $constant.EMBEDDEDDATA.mmedaddress;
	$name = $name -replace '\s',''
	if ($address) {
		$unused = $builder.AppendLine("$name $address l")
	}
}

foreach ($table in $xdf.XDFFORMAT.XDFTABLE)
{
	$columns = $table.XDFAXIS[0].indexcount;
	$rows = $table.XDFAXIS[1].indexcount;

	if ($columns -eq 1)
	{
		if ($rows -eq 1)
		{
			$name = "" # this is a checksum 'table' and the name will be clear enough
		}
		else
		{
			$name = "CurveTable" + $rows + "Rows"
		}
	}
	else
	{
		if ($rows -eq 1)
		{
			$name = "CurveTable" + $columns + "Columns"
		}
		else 
		{
			$name = "SurfaceTable" + $columns + "x" + $rows
		}
	}

	$name = $name + "" + $table.title

	$address = $table.XDFAXIS[$table.XDFAXIS.Length - 1].EMBEDDEDDATA.mmedaddress;
	$name = $name -replace '\s',''

	if ($address) {
		$unused = $builder.AppendLine("$name $address l")
	}
}


Out-File -FilePath ($SourceXdf + ".ghidra") -InputObject $builder.ToString() -Encoding ASCII