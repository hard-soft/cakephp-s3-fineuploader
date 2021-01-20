<?php

/**
 * Based on
 * https://github.com/FineUploader/php-laravel-s3-server/blob/master/ExampleController.php
 *
 */

namespace S3Fineuploader\Traits;

use Aws\S3\S3Client;

trait UploaderMethods {
    // These assume you have the associated AWS keys stored in
    // the associated system environment variables
    private $clientPrivateKey    = null; #$_ENV['AWS_CLIENT_SECRET_KEY'];
    
    // These two keys are only needed if the delete file feature is enabled
    // or if you are, for example, confirming the file size in a successEndpoint
    // handler via S3's SDK, as we are doing in this example.
    private $serverPublicKey     = null; #$_ENV['AWS_SERVER_PUBLIC_KEY'];
    private $serverPrivateKey    = null; #$_ENV['AWS_SERVER_PRIVATE_KEY'];

    // The following variables are used when validating the policy document
    // sent by the uploader. 
    private $expectedBucketName  = null; #$_ENV['S3_BUCKET_NAME'];
    private $expectedHostName    = null; #$_ENV['S3_HOST_NAME']; // v4-only
    
    // $expectedMaxSize is the value you set the sizeLimit property of the 
    // validation option. We assume it is `null` here. If you are performing
    // validation, then change this to match the integer value you specified
    // otherwise your policy document will be invalid.
    // http://docs.fineuploader.com/branch/develop/api/options.html#validation-option
    private $expectedMaxSize = null;


    private function _config ($config = []) {
        $vars = [
            'clientPrivateKey'  => false,
            'serverPublicKey'   => false,
            'serverPrivateKey'  => false,
            'expectedBucketName'=> false,
            'expectedHostName'  => false,
            'expectedMaxSize'   => false,
        ];
        foreach ($vars as $k => $dependent) {
            if (!empty($config[$k])) {
                $this->{$k} = $config[$k];
            } else {
                if ($dependent) {
                    throw new Exception("configuration value not set: {$k}");
                }
            }
        }
    }

    public function endpoint () {
        // This second conditional will only ever evaluate to true if
        // the delete file feature is enabled
        if ($this->request->is('delete')) {
            $this->deleteObject();
        }
        // This is all you really need if not using the delete file feature
        // and not working in a CORS environment
        else if	($this->request->is(['post', 'put'])) {
            // Assumes the successEndpoint has a parameter of "success" associated with it,
            // to allow the server to differentiate between a successEndpoint request
            // and other POST requests (all requests are sent to the same endpoint in this example).
            // This condition is not needed if you don't require a callback on upload success.
            if (isset($_REQUEST["success"])) {
                $this->verifyFileInS3($this->shouldIncludeThumbnail());
            } else {
                $this->signRequest();
            }
        }
        exit;
    }

    private function getS3Client() {
        return S3Client::factory([
            'key'       => $this->serverPublicKey,
            'secret'    => $this->serverPrivateKey,
            'region'    => 'eu-central-1',
            'version'   => 'latest'
        ]);
    }

    // Only needed if the delete file feature is enabled
    private function deleteObject() {
        $this->getS3Client()->deleteObject([
            'Bucket'    => $_REQUEST['bucket'],
            'Key'       => $_REQUEST['key']
        ]);
    }

    private function signRequest() {
        header('Content-Type: application/json');

        $responseBody       = file_get_contents('php://input');
        $contentAsObject    = json_decode($responseBody, true);
        $jsonContent        = json_encode($contentAsObject);
        if (!empty($contentAsObject["headers"])) {
            $this->signRestRequest($contentAsObject["headers"]);
        } else {
            $this->signPolicy($jsonContent);
        }
    }

    private function signRestRequest($headersStr) {
        $version = isset($_REQUEST["v4"]) ? 4 : 2;
        if ($this->isValidRestRequest($headersStr, $version)) {
            if ($version == 4) {
                $response = ['signature' => $this->signV4RestRequest($headersStr)];
            }
            else {
                $response = ['signature' => $this->sign($headersStr)];
            }

            echo json_encode($response);
        } else {
            echo json_encode(["invalid" => true]);
        }
    }

    private function isValidRestRequest($headersStr, $version) {
        if ($version == 2) {
            $pattern = "/\/$this->expectedBucketName\/.+$/";
        }
        else {
            $pattern = "/host:$this->expectedHostName/";
        }

        preg_match($pattern, $headersStr, $matches);

        return count($matches) > 0;
    }

    private function signPolicy($policyStr) {
        $policyObj = json_decode($policyStr, true);

        if ($this->isPolicyValid($policyObj)) {
            $encodedPolicy = base64_encode($policyStr);

            if (isset($_REQUEST["v4"])) {
                $response = ['policy' => $encodedPolicy, 'signature' => $this->signV4Policy($encodedPolicy, $policyObj)];
            } else {
                $response = ['policy' => $encodedPolicy, 'signature' => $this->sign($encodedPolicy)];
            }
            echo json_encode($response);
        } else {
            echo json_encode(["invalid" => true]);
        }
    }

    private function isPolicyValid($policy) {
        $conditions = $policy["conditions"];
        $bucket = null;
        $parsedMaxSize = null;

        for ($i = 0; $i < count($conditions); ++$i) {
            $condition = $conditions[$i];

            if (isset($condition["bucket"])) {
                $bucket = $condition["bucket"];
            }
            else if (isset($condition[0]) && $condition[0] == "content-length-range") {
                $parsedMaxSize = $condition[2];
            }
        }
        return $bucket == $this->expectedBucketName && $parsedMaxSize == (string)$this->expectedMaxSize;
    }

    private function sign($stringToSign) {
        return base64_encode(hash_hmac(
            'sha1',
            $stringToSign,
            $this->clientPrivateKey,
            true
        ));
    }

    private function signV4Policy($stringToSign, $policyObj) {
        foreach ($policyObj["conditions"] as $condition) {
            if (isset($condition["x-amz-credential"])) {
                $credentialCondition = $condition["x-amz-credential"];
            }
        }

        $pattern = "/.+\/(.+)\\/(.+)\/s3\/aws4_request/";
        preg_match($pattern, $credentialCondition, $matches);

        $dateKey                = hash_hmac('sha256', $matches[1], 'AWS4' . $this->clientPrivateKey, true);
        $dateRegionKey          = hash_hmac('sha256', $matches[2], $dateKey, true);
        $dateRegionServiceKey   = hash_hmac('sha256', 's3', $dateRegionKey, true);
        $signingKey             = hash_hmac('sha256', 'aws4_request', $dateRegionServiceKey, true);

        return hash_hmac('sha256', $stringToSign, $signingKey);
    }

    private function signV4RestRequest($rawStringToSign) {
        $pattern = "/.+\\n.+\\n(\\d+)\/(.+)\/s3\/aws4_request\\n(.+)/s";
        preg_match($pattern, $rawStringToSign, $matches);

        $hashedCanonicalRequest = hash('sha256', $matches[3]);
        $stringToSign = preg_replace("/^(.+)\/s3\/aws4_request\\n.+$/s", '$1/s3/aws4_request'."\n".$hashedCanonicalRequest, $rawStringToSign);

        $dateKey                = hash_hmac('sha256', $matches[1], 'AWS4' . $this->clientPrivateKey, true);
        $dateRegionKey          = hash_hmac('sha256', $matches[2], $dateKey, true);
        $dateRegionServiceKey   = hash_hmac('sha256', 's3', $dateRegionKey, true);
        $signingKey             = hash_hmac('sha256', 'aws4_request', $dateRegionServiceKey, true);

        return hash_hmac('sha256', $stringToSign, $signingKey);
    }

    // This is not needed if you don't require a callback on upload success.
    private function verifyFileInS3($includeThumbnail) {
        $bucket = $_REQUEST["bucket"];
        $key    = $_REQUEST["key"];

        // If utilizing CORS, we return a 200 response with the error message in the body
        // to ensure Fine Uploader can parse the error message in IE9 and IE8,
        // since XDomainRequest is used on those browsers for CORS requests.  XDomainRequest
        // does not allow access to the response body for non-success responses.
        if (isset($this->expectedMaxSize) && $this->getObjectSize($bucket, $key) > $this->expectedMaxSize) {
            // You can safely uncomment this next line if you are not depending on CORS
            header("HTTP/1.0 500 Internal Server Error");
            $this->deleteObject();
            echo json_encode(["error" => "File is too big!", "preventRetry" => true]);
        } else {
            $link = $this->getTempLink($bucket, $key);
            $response = ["tempLink" => $link];

            if ($includeThumbnail) {
                $response["thumbnailUrl"] = $link;
            }
            echo json_encode($response);
        }
    }

    // Provide a time-bombed public link to the file.
    private function getTempLink($bucket, $key) {
        $client = $this->getS3Client();
        $url = "{$bucket}/{$key}";
        $request = $client->get($url);

        return $client->createPresignedUrl($request, '+15 minutes');
    }

    private function getObjectSize($bucket, $key) {
        $objInfo = $this->getS3Client()->headObject(array(
            'Bucket'    => $bucket,
            'Key'       => $key
        ));
        return $objInfo['ContentLength'];
    }

    // Return true if it's likely that the associate file is natively
    // viewable in a browser.  For simplicity, just uses the file extension
    // to make this determination, along with an array of extensions that one
    // would expect all supported browsers are able to render natively.
    private function isFileViewableImage($filename) {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $viewableExtensions = ["jpeg", "jpg", "gif", "png"];

        return in_array($ext, $viewableExtensions);
    }

    // Returns true if we should attempt to include a link
    // to a thumbnail in the uploadSuccess response.  In it's simplest form
    // (which is our goal here - keep it simple) we only include a link to
    // a viewable image and only if the browser is not capable of generating a client-side preview.
    private function shouldIncludeThumbnail() {
        $filename = $_REQUEST["name"];
        $isPreviewCapable = $_REQUEST["isBrowserPreviewCapable"] == "true";
        $isFileViewableImage = $this->isFileViewableImage($filename);

        return !$isPreviewCapable && $isFileViewableImage;
    }
}