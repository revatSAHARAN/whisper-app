require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const session = require('express-session');                                 
const passport = require("passport");                                       
const passportLocalMongoose = require("passport-local-mongoose");              
const GoogleStrategy = require('passport-google-oauth20').Strategy;           
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({extended:true}));


app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));


mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false });
mongoose.set("useCreateIndex", true);

const secretSchema = mongoose.Schema({
     name: String 
    });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    googleName: String,
    secrets: [secretSchema]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

           
app.use(passport.initialize());         
app.use(passport.session());       

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URI || "http://localhost:3000/auth/google/secrets"
    // userProfileURL: "https://www.gooleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id, googleName: profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req,res)=>{
    res.render("home");          
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", (req,res)=>{
    res.render("login");          
});
app.get("/register", (req,res)=>{
    res.render("register");          
});

app.get("/secrets", (req,res)=>{
    
    User.find({secrets: {$ne: null}},(err,foundUsers)=>{
        if(err){
            console.log(err);
        } else {
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
                // console.log(foundUsers[0].secrets[1].name);
            }
        }
    });

});

app.get("/submit", (req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit");
    } else{
        res.redirect("/login");
    }
});

app.get("/logout", (req,res)=>{
    req.logout();
    res.redirect("/");
});

app.post("/submit", (req,res)=>{
    // const submittedSecret = req.body.secret;

    // const newSecret = new Secret({
    //     secret: submittedSecret
    // });

    // User.findById(req.user.id, (err, foundUser)=>{
    //     if(err){
    //         console.log(err);
    //     } else{
    //         if(foundUser){
    //             // foundUser.secret = submittedSecret;
    //             foundUser.secret.push(newSecret);
    //             foundUser.save(function(){
    //                 res.redirect("/secrets");
    //             });
    //         }
    //     }
    // });


var newSecret = req.body.secret;
User.findOneAndUpdate({ _id: req.user.id }, { $push:{secrets: { name: newSecret  }} }, function (error, success) {
        if (error) {
            console.log(error);
        } else {
            success.save(function(err){
                if(err){
                    console.log(err)
                } else{
                    res.redirect("/secrets");
                }
            });

        }
    });


});

app.post("/register", (req,res)=>{
    User.register({username: req.body.username}, req.body.password, (err, user)=>{
        if(err){
            console.log(err);
            res.redirect("/register");
        } else{
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req,res)=>{
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req,res, function(err){
                if(!err){
                    res.redirect("/secrets");
                } else{
                    res.redirect("/register");
                }
            });
        }
    });

});





const PORT = process.env.PORT || 3000;
  
  app.listen(PORT, console.log(`Server started on ${PORT}`));