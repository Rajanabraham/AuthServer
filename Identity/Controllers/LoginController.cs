using Azure.Core;
using Identity.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.Text;
using Twilio;
using Twilio.Http.BearerToken;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly TwilioSettings _twilioSettings;
        private readonly ExtensionGrantCredentials _extensionGreanCredentials;
       
        public LoginController(UserManager<IdentityUser> userManager, IOptions<TwilioSettings> twilioSettings, IOptions<ExtensionGrantCredentials> extensionGreanCredentials)
        {
            _userManager = userManager;
            _twilioSettings = twilioSettings.Value;
            _extensionGreanCredentials = extensionGreanCredentials.Value;
        }

        [HttpPost]
        public async Task<IActionResult> MobileLogin(string? phoneNumber)
        {
            if (string.IsNullOrEmpty(phoneNumber))
            {
                return BadRequest("Phone number is required.");
            }

            // Normalize phone number (optional, depends on your storage format)
            var normalizedPhoneNumber = phoneNumber.Trim();

            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == normalizedPhoneNumber);
            if (user == null)
            {
                string email = "test" + "@testmail.com";
                IdentityUser identityuser = new IdentityUser
                {
                    Id = "12345",  
                    UserName = normalizedPhoneNumber,
                    Email = email,
                    PhoneNumber = normalizedPhoneNumber, 
                };
                var result = await _userManager.CreateAsync(identityuser);

            }

            var otp = HelperService.GenerateOtp();

            // Initialize Twilio with injected settings
            TwilioClient.Init(_twilioSettings.AccountSid, _twilioSettings.AuthToken);

            var message = await MessageResource.CreateAsync(
                body: $"Your OTP is: {otp}",
                from: new PhoneNumber(_twilioSettings.PhoneNumber),
                to: new PhoneNumber(normalizedPhoneNumber)
            );

            if (message.ErrorCode != null)
            {
                return StatusCode(500, $"Failed to send OTP: {message.ErrorMessage}");
            }

            return Ok(new { Message = "OTP sent successfully.", Otp = otp });
        }

        [HttpPost]
        [Route("VerifyOtp")]
        public async Task<TokenDto> VerifyOtp(string phoneNumber , string code)
        {
            var normalizedPhoneNumber = phoneNumber.Trim();
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == normalizedPhoneNumber);
            //token generate method
            HttpResponseMessage httpResponseMessage = await TokenGenerate(user);
            if (httpResponseMessage.IsSuccessStatusCode)
            {
                // Read the content from the HTTP response and return it
                var tokenDto = JsonConvert.DeserializeObject<TokenDto>(await httpResponseMessage.Content.ReadAsStringAsync());
                string response =await httpResponseMessage.Content.ReadAsStringAsync();
                return tokenDto;
            }
            else
            {
                // Handle the case where the token generation failed (e.g., return an error or null)
                throw new Exception("Token generation failed");
            }

        }

        private async Task<HttpResponseMessage> TokenGenerate(dynamic identityUserDto)
        {
            // Create an instance of HttpClient manually
            var client = new HttpClient();

            // Prepare the form data for the token request (using URL-encoded format)
            var formData = new Dictionary<string, string>
                {
                    { "grant_type", "passwordless" },  // Custom grant type
                    { "client_id", _extensionGreanCredentials.ClientId },  // Your client ID
                    { "phone_number", identityUserDto.PhoneNumber },  // User's phone number
                    { "scope", _extensionGreanCredentials.Scope }  // The scope
                };

            // Encode the form data as application/x-www-form-urlencoded
            var content = new FormUrlEncodedContent(formData);

            // Make the token request to the OpenIddict server
            HttpResponseMessage response;

            try
            {
                // Send a POST request with form-encoded data
                response = await client.PostAsync($"{_extensionGreanCredentials.AuthServer}/connect/token", content);
                string responseContent = await response.Content.ReadAsStringAsync();
                // Ensure success status code (this will throw an exception if the status is not 2xx)
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
              
                // Log or handle the exception as needed

                throw new InvalidOperationException("An error occurred while requesting the token", ex);
            }

            // Read the response body
            //string responseContent = await response.Content.ReadAsStringAsync();

            // If the response is unsuccessful, throw an error with the response content
            //if (!response.IsSuccessStatusCode)
            //{
            //    throw new InvalidOperationException($"Error from token endpoint: {responseContent}");
            //}

            // Return the response object for further processing
            return response;
        }



    }
}
