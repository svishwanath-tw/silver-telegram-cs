using System;
using System.IO;
using System.Net;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;

public class MingleClient
{
	private string HostUrl { get; set; }
	private string ProjectIdentifier { get; set; }
	private string AccessKeyId { get; set; }
	private string SecretAccessKey { get; set; }
	private const string CONTENT_TYPE = "application/xml";

	public MingleClient(string hostUrl, string projectIdentifier, string accessKeyId, string secretAccessKey)
	{
		this.HostUrl = hostUrl;
		this.ProjectIdentifier = projectIdentifier;
		this.AccessKeyId = accessKeyId;
		this.SecretAccessKey = secretAccessKey;
	}

	private string CalculateMd5Hash(string input)
	{
		var md5 = MD5.Create();
		var inputBytes = Encoding.ASCII.GetBytes(input);
		var hash = md5.ComputeHash(inputBytes);
		return BitConverter.ToString(hash);
	}

	private string CalculateHmac(string canonicalString)
	{
		using (var hmac = new HMACSHA1(Encoding.ASCII.GetBytes(this.SecretAccessKey)))
		{
			hmac.Initialize();
			var hashValue = hmac.ComputeHash(Encoding.ASCII.GetBytes(canonicalString));
			return Convert.ToBase64String(hashValue);
		}
	}

	private string CardUrl(string CardNumber)
	{
		return string.Format("{0}{1}", this.HostUrl, CardUrlPath(CardNumber));
	}

	private string CardUrlPath(string CardNumber)
	{
		return string.Format("/api/v2/projects/{0}/cards/{1}.xml", this.ProjectIdentifier, CardNumber);
	}

	private string AllCardsUrlPath()
	{
		return string.Format("/api/v2/projects/{0}/cards.xml", this.ProjectIdentifier);
	}

	private string AllCardsUrl()
	{
		return string.Format("{0}{1}", this.HostUrl, AllCardsUrlPath());
	}

	private void Sign(HttpWebRequest request)
	{
		var formattedDate = DateTime.Now.ToString("r");
		var contentMd5 = CalculateMd5Hash(string.Empty); //This is for get request. For post, you will need to send request.Body to calculateMd5Hash()
		var requestPath = request.RequestUri.AbsolutePath;
		var canonicalString = string.Format("{0},{1},{2},{3}", CONTENT_TYPE, contentMd5, requestPath, formattedDate);
		var hmacSignature = CalculateHmac(canonicalString);

		request.ContentType = CONTENT_TYPE;
		var privateMethodWorkaroundForDate = request.Headers.GetType().GetMethod("AddWithoutValidate", BindingFlags.Instance | BindingFlags.NonPublic);
		privateMethodWorkaroundForDate.Invoke(request.Headers, new[] { "Date", formattedDate });
		request.Headers["Content-MD5"] = contentMd5;
		request.Headers["Authorization"] = string.Format("APIAuth {0}:{1}", this.AccessKeyId, hmacSignature);
		return;
	}

	private string doGetRequest(string url) {
		HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
		Sign(request);
		HttpWebResponse response = (HttpWebResponse)request.GetResponse();
		Stream resStream = response.GetResponseStream();
		StreamReader objReader = new StreamReader(resStream);

		return objReader.ReadToEnd();
	}

	public string GetCard(string CardNumber)
	{
		return doGetRequest(CardUrl(CardNumber));
	}

	public string GetAllCards()
	{
		return doGetRequest(AllCardsUrl());
	}


	public static void Main (string[] args)
	{
		if(args.Length < 4 || args.Length > 5)
		{
			Console.WriteLine("Usage: MingleClient mingle_host_url project_identifier access_key_id secret_access_key [card_number].\nIf card number is omitted, you will get the first page of API results");
			return;
		}
		var mingleHost = args[0];
		var projectIdentifier = args[1];
		var accessKeyId = args[2];
		var secretAccessKey = args[3];
		var mingleClient = new MingleClient(mingleHost, projectIdentifier, accessKeyId, secretAccessKey);


		if(args.Length == 5)
		{
			string cardNumber = args[4];
			Console.WriteLine(mingleClient.GetCard(cardNumber));
		}
		else
		{
			Console.WriteLine(mingleClient.GetAllCards());
		}
	}
}

