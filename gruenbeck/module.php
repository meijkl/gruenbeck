<?php
	class Gruenbeck extends IPSModule {

		public function Create()
		{
			//Never delete this line!
			parent::Create();

			//Properties
			$this->RegisterPropertyString('Username', '');
			$this->RegisterPropertyString('Password', '');

		}

		public function Destroy()
		{
			//Never delete this line!
			parent::Destroy();
		}

		public function ApplyChanges()
		{
			//Never delete this line!
			parent::ApplyChanges();
		}

		public function GB_Login()
		{
			$codeChallange = "cgCaF9zlf7HGlHsuQepqKGk1fLqmnFQ1E3EyWB4qiPs"; //Wert aus IOBroker Funktion entnommen
			$this->SendAction("https://gruenbeckb2c.b2clogin.com/a50d35c1-202f-4da7-aa87-76e51a3098c6/b2c_1a_signinup/oauth2/v2.0/authorize?x-client-Ver=0.8.0&state=NjkyQjZBQTgtQkM1My00ODBDLTn3MkYtOTZCQ0QyQkQ2NEE5&client_info=1&response_type=code&code_challenge_method=S256&x-app-name=Gr%C3%BCnbeck&x-client-OS=14.3&x-app-ver=1.2.1&scope=https%3A%2F%2Fgruenbeckb2c.onmicrosoft.com%2Fiot%2Fuser_impersonation%20openid%20profile%20offline_access&x-client-SKU=MSAL.iOS&code_challenge=" . $codeChallange . "&x-client-CPU=64&client-request-id=F2929DED-2C9D-49F5-A0F4-31215427667C&redirect_uri=msal5a83cc16-ffb1-42e9-9859-9fbf07f36df8%3A%2F%2Fauth&client_id=5a83cc16-ffb1-42e9-9859-9fbf07f36df8&haschrome=1&return-client-request-id=true&x-client-DM=iPhone");
		}

		private function SendAction($url)
		{
			//Erster Aufruf | funktioniert einwandfrei
			$this->SendDebug('SendAction', $url, 0);
	
			$options = [
				'http' => [
					'method'  => 'GET',
					'header'  => ''
				]
			];

			$context = stream_context_create($options);

			$result = file_get_contents($url, false, $context);

			if ($result === false) {
				die('Fetching data failed!');
			}

			//Benötigte Daten aus der Antword filtern
			$jsonStart = strpos($result, "var SETTINGS = ") + 15;
			$jsonEnd = strpos($result, ',"sanitizerPolicy"', $jsonStart);
			$jsonString = json_decode(substr($result, $jsonStart, $jsonEnd - $jsonStart) . "}", true);
			$csrf = $jsonString['csrf'];
			$transId = $jsonString['transId'];
			$jsonStart = strpos($result, '"hosts":') + 8;
			$jsonEnd = strpos($result, '"locale') - 1;
			$jsonString = json_decode(substr($result, $jsonStart, $jsonEnd - $jsonStart), true);
			$tenant = $jsonString['tenant'];
			$policy = $jsonString['policy'];

			$this->SendDebug('Success',$result, 0);

			$setCookie9 = $http_response_header[9];
			$setCookie10 = $http_response_header[10];
			$this->SendDebug("Cookies", print_r($http_response_header, 1), 0);
			$cookie = substr($setCookie9, 11, strpos($setCookie9, "; ", 11) - 11 ) . "; " . substr($setCookie10, 11, strpos($setCookie10, "; ", 11) - 11 );

			//Zweiter Aufruf | fehlerhaft
			$data = [
				"request_type" => "RESPONSE",
				"logonIdentifier" => $this->ReadPropertyString('Username'),
				"password" => $this->ReadPropertyString('Password')
			];
			$query = http_build_query($data);
			$options = [
				'http' => [
					'method'  => 'POST',
					'header'  => "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n".
								 "Content-Length: ". strlen($query). "\r\n".
								 "X-CSRF-TOKEN: $csrf\r\n".
								 //"Accept: application/json, text/javascript, */*; q=0.01\r\n".
								 "X-Request-With: XMLHttpRequest\r\n".
								 "Origin: https://gruenbeckb2c.b2clogin.com\r\n".
								 "Referer: https://gruenbeckb2c.b2clogin.com/a50d35c1-202f-4da7-aa87-76e51a3098c6/b2c_1a_signinup/oauth2/v2.0/authorize?x-client-Ver=0.8.0&state=NjkyQjZBQTgtQkM1My00ODBDLTn3MkYtOTZCQ0QyQkQ2NEE5&client_info=1&response_type=code&code_challenge_method=S256&x-app-name=Gr%C3%BCnbeck&x-client-OS=14.3&x-app-ver=1.2.1&scope=https%3A%2F%2Fgruenbeckb2c.onmicrosoft.com%2Fiot%2Fuser_impersonation%20openid%20profile%20offline_access&x-client-SKU=MSAL.iOS&code_challenge=" . $codeChallange . "&x-client-CPU=64&client-request-id=F2929DED-2C9D-49F5-A0F4-31215427667C&redirect_uri=msal5a83cc16-ffb1-42e9-9859-9fbf07f36df8%3A%2F%2Fauth&client_id=5a83cc16-ffb1-42e9-9859-9fbf07f36df8&haschrome=1&return-client-request-id=true&x-client-DM=iPhone\r\n".
								 "Cookie: $cookie\r\n",
								 //"User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 12_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1\r\n",
					'content' => $query
				]
			];

			$context = stream_context_create($options);

			$url = "https://gruenbeckb2c.b2clogin.com" . $tenant . "/SelfAsserted?tx=" . $transId . "&p=" . $policy;
			$result = file_get_contents($url, false, $context);

			if ($result === false) {
				die('Fetching data failed!');
			}
		}
	}
