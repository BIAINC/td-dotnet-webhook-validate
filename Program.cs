using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace WebhookValidation
{
  internal static class EpochTime
  {
    private static DateTime _epochStartDateTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static DateTime ConvertEpochToDateTime(long seconds)
    {
      return _epochStartDateTime.AddSeconds(seconds);
    }

    public static long ConvertDateTimeToEpoch(this DateTime datetime)
    {
      if (datetime < _epochStartDateTime) return 0;

      return Convert.ToInt64((datetime.ToUniversalTime() - _epochStartDateTime).TotalSeconds);
    }
  }

  class Program
  {
    internal static readonly UTF8Encoding SafeUTF8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
    static void Main(string[] args)
    {
      var body = "{\"id\":\"en_7d45092fc1b173371adad416071fc999\",\"type\":\"event_notification\",\"api-version\":\"2018-01-01\",\"meta\":{\"request\":{\"type\":\"test.event\",\"event-time\":\"2018-02-12T00:40:12Z\",\"event-id\":\"evt_a5c8b7da734b16415e45eaf43bfcbf6c\"}},\"data\":{\"type\":\"hello\",\"attributes\":{\"ping\":\"2018-02-12T00:40:12Z\"}}}";
      var header = "t=1518396013,v1=5e74a4786626a887c7de42bdc072c9e6ca471cd6b7509247b9ddff6cdca48c15";

      var secret = "3a9c02b8-0bc2-422f-8f97-1cb0da14a514";

      var result = ConstructEvent(body, header, secret);
      Console.WriteLine(result);
    }

    public static string ConstructEvent(string json, string stripeSignatureHeader, string secret, int tolerance = 300)
    {
      var signatureItems = parseStripeSignature(stripeSignatureHeader);
      var signature = string.Empty;

      try
      {
        signature = computeSignature(secret, signatureItems["t"].FirstOrDefault(), json);
      }
      catch (EncoderFallbackException)
      {
        return "The webhook cannot be processed because the signature cannot be calculated.";
      }

      if (!isSignaturePresent(signature, signatureItems["v1"]))
        return "The signature for the webhook does not match any of the signatures in the X-TD-Signature header.";

      var utcNow = DateTime.UtcNow.ConvertDateTimeToEpoch();
      var webhookUtc = Convert.ToInt32(signatureItems["t"].FirstOrDefault());

      if (utcNow - webhookUtc > tolerance)
        return "The webhook matched signature, but the current timestamp is above the allowed tolerance.";

      return "Webhook event is valid and verified";
    }

    private static ILookup<string, string> parseStripeSignature(string stripeSignatureHeader)
    {
      return stripeSignatureHeader.Trim()
          .Split(',')
          .Select(item => item.Trim().Split('='))
          .ToLookup(item => item[0], item => item[1]);
    }

    private static bool isSignaturePresent(string signature, IEnumerable<string> signatures)
    {
      return signatures.Any(key => secureCompare(key, signature));
    }

    private static string computeSignature(string secret, string timestamp, string payload)
    {
      var secretBytes = SafeUTF8.GetBytes(secret);
      var payloadBytes = SafeUTF8.GetBytes($"{timestamp}.{payload}");

      using (var cryptographer = new HMACSHA256(secretBytes))
      {
        var hash = cryptographer.ComputeHash(payloadBytes);
        return BitConverter.ToString(hash).Replace("-", "").ToLower();
      }
    }

    private static bool secureCompare(string a, string b)
    {
      if (a.Length != b.Length) return false;

      var result = 0;

      for (var i = 0; i < a.Length; i++)
      {
        result |= a[i] ^ b[i];
      }

      return result == 0;
    }

  }
}


