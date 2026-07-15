<?php
$hasil_ssl = null;
$error = null;

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Bersihkan input domain
    $domain_target = trim($_POST['domain']);
    $domain_bersih = preg_replace('#^https?://#', '', $domain_target);
    $domain_bersih = explode('/', rtrim($domain_bersih, '/'))[0];

    if (!empty($domain_bersih)) {

        try {

            // Membuat SSL Context
            $streamContext = stream_context_create([
                "ssl" => [
                    "capture_peer_cert" => true,
                    "verify_peer" => false,
                    "verify_peer_name" => false,
                ]
            ]);

            // Membuka koneksi HTTPS
            $client = @stream_socket_client(
                "ssl://" . $domain_bersih . ":443",
                $errorNumber,
                $errorString,
                10,
                STREAM_CLIENT_CONNECT,
                $streamContext
            );

            if ($client) {

                // Mengambil sertifikat SSL
                $params = stream_context_get_params($client);
                $cert_resource = $params['options']['ssl']['peer_certificate'];

                // Parsing sertifikat
                $hasil_ssl = openssl_x509_parse($cert_resource);

                // Export format PEM
                openssl_x509_export($cert_resource, $pem_format);
                $hasil_ssl['pem_raw'] = $pem_format;

                fclose($client);

            } else {

                $error = "Connection failed! Pastikan domain aktif dan menggunakan HTTPS.";

            }

        } catch (Exception $e) {

            $error = "Terjadi Kesalahan : " . $e->getMessage();

        }

    } else {

        $error = "Masukkan nama domain.";

    }

}
?>

<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>SSL/TLS Analyzer</title>

<style>

body{
    font-family:Arial, Helvetica, sans-serif;
    background:#f5f5f5;
    margin:0;
    padding:30px;
}

.container{
    width:900px;
    margin:auto;
    background:white;
    padding:25px;
    border-radius:10px;
    box-shadow:0 0 10px rgba(0,0,0,.2);
}

h2{
    text-align:center;
    color:#059669;
}

input[type=text]{
    width:70%;
    padding:10px;
    font-size:16px;
}

button{
    padding:11px 20px;
    background:#059669;
    color:white;
    border:none;
    cursor:pointer;
}

button:hover{
    background:#047857;
}

table{
    width:100%;
    border-collapse:collapse;
    margin-top:20px;
}

table td{
    border:1px solid #ddd;
    padding:10px;
}

th{
    background:#059669;
    color:white;
    padding:10px;
}

.success{
    background:#ecfdf5;
    padding:15px;
    margin-top:20px;
    border-left:5px solid green;
}

.error{
    background:#fee2e2;
    color:red;
    padding:15px;
    margin-top:20px;
    font-weight:bold;
    border-left:5px solid red;
}

textarea{
    width:100%;
    height:300px;
    background:#111827;
    color:#22c55e;
    padding:10px;
}

</style>

</head>

<body>

<div class="container">

<h2>SSL/TLS Analyzer</h2>

<form method="POST">

<label>Masukkan Domain :</label><br><br>

<input
type="text"
name="domain"
placeholder="Contoh : google.com"
required>

<button type="submit">
Analisis
</button>

</form>

<?php if($error){ ?>

<div class="error">

<?= $error ?>

</div>

<?php } ?>

<?php if($hasil_ssl){ ?>

<div class="success">

<h3>Informasi Sertifikat Digital</h3>

<table>

<tr>

<th>Parameter</th>

<th>Hasil</th>

</tr>

<tr>

<td>Domain (CN)</td>

<td><?= htmlspecialchars($hasil_ssl['subject']['CN'] ?? '-') ?></td>

</tr>

<tr>

<td>Organisasi</td>

<td><?= htmlspecialchars($hasil_ssl['subject']['O'] ?? '-') ?></td>

</tr>

<tr>

<td>Negara</td>

<td><?= htmlspecialchars($hasil_ssl['subject']['C'] ?? '-') ?></td>

</tr>

<tr>

<td>Certification Authority (Issuer)</td>

<td><?= htmlspecialchars($hasil_ssl['issuer']['O'] ?? $hasil_ssl['issuer']['CN']) ?></td>

</tr>

<tr>

<td>Berlaku Mulai</td>

<td><?= date("d F Y H:i:s",$hasil_ssl['validFrom_time_t']); ?></td>

</tr>

<tr>

<td>Berlaku Hingga</td>

<td><?= date("d F Y H:i:s",$hasil_ssl['validTo_time_t']); ?></td>

</tr>

<tr>

<td>Versi Sertifikat</td>

<td><?= htmlspecialchars($hasil_ssl['version']) ?></td>

</tr>

<tr>

<td>Serial Number</td>

<td><?= htmlspecialchars($hasil_ssl['serialNumber']) ?></td>

</tr>

<tr>

<td>Algoritma Signature</td>

<td><?= htmlspecialchars($hasil_ssl['signatureTypeSN']) ?></td>

</tr>

</table>

<h3>Data Sertifikat (.PEM)</h3>

<textarea readonly><?= htmlspecialchars($hasil_ssl['pem_raw']) ?></textarea>

</div>

<?php } ?>

</div>

</body>
</html>