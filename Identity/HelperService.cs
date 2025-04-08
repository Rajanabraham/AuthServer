namespace Identity
{
    public static class HelperService
    {
        public static string GenerateOtp()
        {
            var random = new Random();
            return random.Next(1000, 9999).ToString(); // 4-digit OTP
        }
    }
}
