using System;
using Xunit;
using IIG.PasswordHashingUtils;

namespace lab2HashingUtils
{
    public class UnitTest1
    {
        string pass = "password";
        string salt = "putted soul(or salt) xD";

      
        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("s")]
        [InlineData("\"")]
        [InlineData(null)]
        [InlineData("default_password")]
        [InlineData("1")]
        public void isHashNotNullWithOnlyDifferentPasswords(string pass)
        {
            Assert.NotNull(PasswordHasher.GetHash(pass));
        }
          [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("s")]
        [InlineData("\"")]
        [InlineData("null")]
        [InlineData("default_password")]
        [InlineData("1")]
        public void areHashesEqualsForSamePass(string pass){
            Assert.Equal(PasswordHasher.GetHash(pass), PasswordHasher.GetHash(pass));
        }

        [Fact]
        public void doesThrowExceptinWhenPassEqNull(){
            Assert.Throws<ArgumentNullException>(() => PasswordHasher.GetHash(null));
        }
        [Fact]
        public void doesThrowExceptinWhenSaltEqNull(){
            Assert.Throws<ArgumentNullException>(() => PasswordHasher.GetHash("default", null));
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData(" ")]
        public void isHashesEqualWhentSaltEqNullOrEmpty(string salt){
            Assert.Equal(PasswordHasher.GetHash(pass), PasswordHasher.GetHash(pass,salt));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(null)]
        // [InlineData(-3)]
        public void isHashesEqualWhenMODADLER32EqNullOr0(uint modAdler32){
            Assert.Equal(PasswordHasher.GetHash(pass), PasswordHasher.GetHash(pass,null,modAdler32));
        }

        
        [Theory]
        [InlineData(" ")]
        [InlineData("def")]
        [InlineData("itShouldHaveBeenTheLongestSaltIHaveEverThoughtOfButIThinkItIsNotTheBiggestThatCanExitstInAllParallelWorldsAndDimensions")]
        [InlineData("_!@#$%^&*()`/")]
        public void areHashesDiffWhenSaltPresents(string salt){
            Assert.NotEqual(PasswordHasher.GetHash(pass),PasswordHasher.GetHash(pass, salt));
        }
        [Theory]
        [InlineData(1)]
        [InlineData(2131232132142)]
        [InlineData(99999)]
        [InlineData(UInt32.MaxValue)]
        public void areHashesDiffWhenModAdlerPresentsAndBiggerThan0(uint modAdler32){
            Assert.NotEqual(PasswordHasher.GetHash(pass),PasswordHasher.GetHash(pass, null, modAdler32));
        }
        

        [Theory]
        [InlineData(" ",0)]
        [InlineData("salt",123)]
        [InlineData(null, 123)]
        [InlineData(null,null)]
        [InlineData("salt", null)]
        public void areHashesEqualsWhenSaltAndADLERMOD32GivenToGetHashAndInitMethods(string salt, uint adletMod32){
            string pass = "passwrod";
            string passWithOnlyGetHashMethod = PasswordHasher.GetHash(pass,salt,adletMod32);
            PasswordHasher.Init(salt,adletMod32);
            string passWithInitMethod = PasswordHasher.GetHash(pass);
            Assert.Equal(passWithInitMethod, passWithOnlyGetHashMethod);
        }


        [Theory]
        [InlineData("парольУкраїнською")]
        [InlineData("парольНаРусском")]
        [InlineData("كلمة السر بالعربية")]
        [InlineData("中文密碼")]
        [InlineData("a")]
        [InlineData("password")]
         public void areHashesDiffWhenUppercase(string pass){
                Assert.NotEqual(PasswordHasher.GetHash(pass), 
                PasswordHasher.GetHash(char.ToUpper(pass[0])+pass.Substring(1)));
        }
         [Theory]
        [InlineData(" ")]
        [InlineData("1")]
        [InlineData("?")]
        public void areHashesDiffWhenUppercaseSpecialChars(string pass){
              Assert.Equal(PasswordHasher.GetHash(pass), 
                PasswordHasher.GetHash(char.ToUpper(pass[0])+pass.Substring(1)));
        }

        [Theory]
        [InlineData(" ", "  ")]
        [InlineData("fgdfg","sdkmso kgfg sd;'")]
        [InlineData("?", "null")]
        [InlineData("2132113"," 12312421")]
         public void areHashesLengthEqualsForDiffParams(string pass,string pass2){
                Assert.Equal(
                PasswordHasher.GetHash(pass).Length,
                PasswordHasher.GetHash(pass2).Length);
        }


        [Fact]
        public void doesHashLengthEq64(){
            Assert.Equal(PasswordHasher.GetHash(pass).Length, 64);
        }
        // [Theory]
        // [InlineData()]
        // [InlineData()]
        // [InlineData()]
        // public void isHashNotNullWhenPassAndSalt(string pass, string salt){

        // }
    }
}
