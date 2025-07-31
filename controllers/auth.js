const mysql= require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const { error } = require('console');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const nodemailer = require('nodemailer');

//create connection
const db = mysql.createConnection({
    host     : process.env.DATABASE_HOST,
    user     : process.env.DATABASE_USER,
    password : process.env.DATABASE_PASSWORD,
    database : process.env.DATABASE
});


// for configuring mail

const transporter = nodemailer.createTransport({
  service: 'Gmail', // or another email service
  auth: {
    user: 'joelanto386@gmail.com',
    pass: 'doqhdasfmcrdvniv'
  }
});

//---------------------------------------------------


exports.login = async (req, res) => {
    try {
      const { email, password } = req.body;
  
      if( !email || !password ) {
        return res.status(400).render('student/login', {
          message: 'Please provide an email and password'
        })
      }
  
      db.query('SELECT * FROM student WHERE email = ?', [email], async (error, results) => {
        console.log(results);
        if( !results || !(await bcrypt.compare(password, results[0].password)) ) {
          res.status(401).render('student/login', {
            message: 'Email or Password is incorrect'
          });

          

        } else {
          const id = results[0].id;
  
          const token = jwt.sign({ id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN
          });
  
          console.log("The token is: " + token);
  
          const cookieOptions = {
            expires: new Date(
              Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
            ),
            httpOnly: true
          }
  
          res.cookie('jwt', token, cookieOptions );
          res.status(200).redirect("/dashboard");
        }
  
      })
  
    } catch (error) {
      console.log(error);
    }
  }
  
  exports.register = (req, res) => {
    console.log(req.body);
  
    const { name, email, password, confirmPassword } = req.body;
  
    db.query('SELECT email FROM student WHERE email = ?', [email], async (error, results) => {
      if(error) {
        console.log(error);
      }
  
      if( results.length > 0 ) {
        return res.render('student/register', {
          message: 'That email is already in use'
        })
      } else if( password !== confirmPassword ) {
        return res.render('student/register', {
          message: 'Passwords do not match'
        });
      }
  
      let hashedPassword = await bcrypt.hash(password, 8);
      console.log(hashedPassword);
  
      db.query('INSERT INTO student SET ?', {name: name, email: email, password: hashedPassword }, (error, results) => {
        if(error) {
          console.log(error);
        } else {
          console.log(results);
          return res.render('student/register', {
            message: 'User registered'
          });
        }
      })
  
  
    });
  
  }
  
  exports.isLoggedIn = async (req, res, next) => {
    // console.log(req.cookies);
    if( req.cookies.jwt) {
      try {
        //1) verify the token
        const decoded = await promisify(jwt.verify)(req.cookies.jwt,
        process.env.JWT_SECRET
        );
  
        console.log(decoded);
  
        //2) Check if the user still exists
        db.query('SELECT * FROM student WHERE id = ?', [decoded.id], (error, result) => {
          console.log(result);
  
          if(!result) {
            return next();
          }
  
          req.user = result[0];
          console.log("user is")
          console.log(req.user);
          return next();
  
        });
      } catch (error) {
        console.log(error);
        return next();
      }
    } else {
      next();
    }
  }
  
  exports.logout = async (req, res) => {
    res.cookie('jwt', 'logout', {
      expires: new Date(Date.now() + 2*1000),
      httpOnly: true
    });
  
    res.status(200).redirect('/');
  }


  exports.admlogin = async (req, res) => {
    try {
      const { email, password } = req.body;
  
      if( !email || !password ) {
        return res.status(400).render('admin/adminlogin', {
          message: 'Please provide an email and password'
        })
      }
  
      db.query('SELECT * FROM admin WHERE email = ?', [email], async (error, results) => {
        console.log(results);
        if( !results || !(await bcrypt.compare(password, results[0].password)) ) {
          res.status(401).render('admin/adminlogin', {
            message: 'Email or Password is incorrect'
          })

          

        } else {
          const id = results[0].id;
  
          const token = jwt.sign({ id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN
          });
  
          console.log("The token is: " + token);
  
          const cookieOptions = {
            expires: new Date(
              Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
            ),
            httpOnly: true
          }
  
          res.cookie('jwt', token, cookieOptions );
          res.status(200).redirect("/admindash");
        }
  
      })
  
    } catch (error) {
      console.log(error);
    }
  }

  exports.admregister = (req, res) => {
    console.log(req.body);
  
    const { name, email, password, confirmPassword } = req.body;
  
    db.query('SELECT email FROM admin WHERE email = ?', [email], async (error, results) => {
      if(error) {
        console.log(error);
      }
  
      if( results.length > 0 ) {
        return res.render('admin/adminregister', {
          message: 'That email is already in use'
        })
      } else if( password !== confirmPassword ) {
        return res.render('admin/adminregister', {
          message: 'Passwords do not match'
        });
      }
  
      let hashedPassword = await bcrypt.hash(password, 8);
      console.log(hashedPassword);
  
      db.query('INSERT INTO admin SET ?', {name: name, email: email, password: hashedPassword }, (error, results) => {
        if(error) {
          console.log(error);
        } else {
          console.log(results);
          return res.render('admin/adminregister', {
            message: 'User registered'
          });
        }
      })
  
  
    });
  
  }
  
  exports.admisLoggedIn = async (req, res, next) => {
    // console.log(req.cookies);
    if( req.cookies.jwt) {
      try {
        //1) verify the token
        const decoded = await promisify(jwt.verify)(req.cookies.jwt,
        process.env.JWT_SECRET
        );
  
        console.log(decoded);
  
        //2) Check if the user still exists
        db.query('SELECT * FROM admin WHERE id = ?', [decoded.id], (error, result) => {
          console.log(result);
  
          if(!result) {
            return next();
          }
  
          req.user = result[0];
          console.log("user is")
          console.log(req.user);
          return next();
  
        });
      } catch (error) {
        console.log(error);
        return next();
      }
    } else {
      next();
    }
  }


  
  exports.complogin = async (req, res) => {
    try {
      const { email, password } = req.body;
  
      if( !email || !password ) {
        return res.status(400).render('company/companylogin', {
          message: 'Please provide an email and password'
        })
      }
  
      db.query('SELECT * FROM company WHERE email = ?', [email], async (error, results) => {
        console.log(results);
        if( !results || !(await bcrypt.compare(password, results[0].password)) ) {
          res.status(401).render('company/companylogin', {
            message: 'Email or Password is incorrect'
          })

          

        } else {
          const id = results[0].id;
  
          const token = jwt.sign({ id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN
          });
  
          console.log("The token is: " + token);
  
          const cookieOptions = {
            expires: new Date(
              Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
            ),
            httpOnly: true
          }
  
          res.cookie('jwt', token, cookieOptions );
          res.status(200).redirect("/compdash");
        }
  
      })
  
    } catch (error) {
      console.log(error);
    }
  }

  exports.compregister = (req, res) => {
    console.log(req.body);
  
    const { name, email, password, confirmPassword } = req.body;
  
    db.query('SELECT email FROM company WHERE email = ?', [email], async (error, results) => {
      if(error) {
        console.log(error);
      }
  
      if( results.length > 0 ) {
        return res.render('company/companyregister', {
          message: 'That email is already in use'
        })
      } else if( password !== confirmPassword ) {
        return res.render('company/companyregister', {
          message: 'Passwords do not match'
        });
      }
  
      let hashedPassword = await bcrypt.hash(password, 8);
      console.log(hashedPassword);
  
      db.query('INSERT INTO company SET ?', {name: name, email: email, password: hashedPassword }, (error, results) => {
        if(error) {
          console.log(error);
        } else {
          console.log(results);
          return res.render('company/companyregister', {
            message: 'User registered'
          });
        }
      })
  
  
    });
  
  }
  
  exports.compisLoggedIn = async (req, res, next) => {
    // console.log(req.cookies);
    if( req.cookies.jwt) {
      try {
        //1) verify the token
        const decoded = await promisify(jwt.verify)(req.cookies.jwt,
        process.env.JWT_SECRET
        );
        console.log('decoded is:');
        console.log(decoded);
  
        //2) Check if the user still exists
        db.query('SELECT * FROM company WHERE id = ?', [decoded.id], (error, result) => {
          console.log(result);
  
          if(!result) {
            return next();
          }
  
          req.user = result[0];
          console.log("user is")
          console.log(req.user);
          return next();
  
        });
      } catch (error) {
        console.log(error);
        return next();
      }
    } else {
      next();
    }
  }


//for image upload functions ----------------------------------------------------------------------------
//and for updating the profile


// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: './public/uploads/',
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 1000000 }, // 1MB limit
  fileFilter: function (req, file, cb) {
    checkFileType(file, cb);
  }
}).single('profile_image');

// Check file type
function checkFileType(file, cb) {
  const filetypes = /jpeg|jpg|png|gif/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb('Error: Images Only!');
  }
}

exports.updateProfile = (req, res, next) => {
  upload(req, res, async (err) => {
    if (err) {
      return res.render('student/studentprofile', { message: err });
    } else {
      try {
        const { name, email, phone_number, city, gender } = req.body;
        let profileImage;

        if (req.file) {
          profileImage = req.file.filename;
        }

        if (req.cookies.jwt) {
          const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);

          // Check if user exists or not
          db.query('SELECT * FROM student WHERE id = ?', [decoded.id], (error, result) => {
            if (error) {
              console.log(error);
              return next();
            }

            req.user = result[0];
            console.log("user is", req.user);

            let updateQuery = 'UPDATE student SET name = ?, email = ?, phone_number = ?, city = ?, gender = ?';
            let queryParams = [name, email, phone_number, city, gender, decoded.id];

            if (profileImage) {
              updateQuery += ', profile_image = ?';
              queryParams = [name, email, phone_number, city, gender, profileImage, decoded.id];
            }

            updateQuery += ' WHERE id = ?';

            db.query(updateQuery, queryParams, (error, results) => {
              if (error) {
                console.log(error);
                return next();
              }
              res.status(200).render('student/studentprofile', {
                message: 'Profile Updated Successfully',
                profileImage:profileImage
              });
            });
          });
        }
      } catch (error) {
        console.log(error);
        return next();
      }
    }
  });
};




/*exports.updateProfile = async (req,res,next)=>{
  try{
    const { name , email , phone_number , city , gender } = req.body;
    

    if(req.cookies.jwt) {
      const decoded = await promisify(jwt.verify)(req.cookies.jwt,process.env.JWT_SECRET);

      //check if user exits or not
      db.query('SELECT * FROM student WHERE id = ?', [decoded.id],async(error,result)=>{
        if(error) {
          console.log(error);
          return next();
        }

        req.user = result[0];
        console.log("user is");
        console.log(req.user);

        db.query('UPDATE student SET name = ? , email = ? , phone_number = ? , city = ? , gender = ?  WHERE id=? ', [name ,email ,phone_number ,city ,gender ,decoded.id],(error,results)=>{
          if(error) {
            console.log(error);
            return next();
          }
          res.status(200).render('student/studentprofile',{
            message: 'Profile Updated Successfully'
          });
        });
        
      });
    }
  }
  catch(error) {
    console.log(error);
    return next();
  }
}
*/

//------------------------------------------------------------------------------------------------------

// Update the password for the logged-in user
exports.updatePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).render('student/changepass', {
        message: 'New password and confirm password do not match'
      });
    }

    if (req.cookies.jwt) {
      const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);

      db.query('SELECT * FROM student WHERE id = ?', [decoded.id], async (error, result) => {
        if (error) {
          console.log(error);
          return next();
        }

        if (!result || !(await bcrypt.compare(oldPassword, result[0].password))) {
          return res.status(401).render('student/changepass', {
            message: 'Old password is incorrect'
          });
        } else {
          const hashedPassword = await bcrypt.hash(newPassword, 8);
          db.query('UPDATE student SET password = ? WHERE id = ?', [hashedPassword, decoded.id], (error, results) => {
            if (error) {
              console.log(error);
              return next();
            }

              res.status(200).render('student/changepass', {
              message: 'Password updated successfully'
              });

              /*res.status(200).send('<script>alert("Password updated successfully"); </script>');*/

              
            });
        
        }
      });
    } else {
      next();
    }
  } catch (error) {
    console.log(error);
    return next();
  }
}


exports.updateCompanyPassword = async (req, res) => {
  try {
    const { oldPassword, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).render('company/changepassword', {
        message: 'New password and confirm password do not match'
      });
    }

    if (req.cookies.jwt) {
      const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);

      db.query('SELECT * FROM company WHERE id = ?', [decoded.id], async (error, result) => {
        if (error) {
          console.log(error);
          return next();
        }

        if (!result || !(await bcrypt.compare(oldPassword, result[0].password))) {
          return res.status(401).render('company/changepassword', {
            message: 'Old password is incorrect'
          });
        } else {
          const hashedPassword = await bcrypt.hash(newPassword, 8);
          db.query('UPDATE company SET password = ? WHERE id = ?', [hashedPassword, decoded.id], (error, results) => {
            if (error) {
              console.log(error);
              return next();
            }

              res.status(200).render('company/changepassword', {
              message: 'Password updated successfully'
              });

              /*res.status(200).send('<script>alert("Password updated successfully"); </script>');*/

              
            });
        
        }
      });
    } else {
      next();
    }
  } catch (error) {
    console.log(error);
    return next();
  }
}


exports.addInterviews = async (req, res, next) => {
  try {
    const { company_name, job_role, job_type, job_description } = req.body;

    if (req.cookies.jwt) {
      const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);

      const newInterview = {
        company_name,
        job_role,
        job_type,
        job_description,
        id: decoded.id
      };

      db.query('INSERT INTO interview SET ?', newInterview, async (error, result) => {
        if (error) {
          console.log(error);
          return next();
        }
        res.status(200).render('company/interviews',{
          message: 'Interview added successfully'
        });
      });
    }

  } catch (error) {
    console.log(error);
    return next();
  }
};


exports.viewInterview = async (req, res, next) => {
  try {
    if (req.cookies.jwt) {
      const decoded = await promisify(jwt.verify)(req.cookies.jwt, process.env.JWT_SECRET);
      const id = decoded.id;

      db.query('SELECT * FROM interview WHERE id = ?', [id], (error, result) => {
        if (error) {
          console.log(error);
          return next();
        }

        req.interviews = result;
        console.log("Interview details are:");
        console.log(req.interviews);
        return next();

      });
    } else {
      return next();
    }
  } catch (error) {
    console.log(error);
    return next();
  }
};

exports.viewInterviewForStudents = async (req, res, next) => {
  try {
      db.query('SELECT * FROM interview', (error, result) => {
        if (error) {
          console.log(error);
          return next();
        }

        req.studentInterviews = result;
        console.log("Interview details are:");
        console.log(req.studentInterviews);
        return next();

      });
  } catch (error) {
    console.log(error);
    return next();
  }
};


exports.viewInterviewForStudentsToApply = async (req, res, next) => {
  try {
      db.query('SELECT user_id FROM interview', (error, result) => {
        if (error) {
          console.log(error);
          return next();
        }

        req.interviewid = result[0];
        console.log("Interview id is:");
        console.log(req.interviewid);
        return next();

      });
  } catch (error) {
    console.log(error);
    return next();
  }
};


exports.deleteInterview = async (req,res,next) =>{
  try {
    if(req.cookies.jwt) {
      const decoded = await promisify(jwt.verify)(req.cookies.jwt,process.env.JWT_SECRET);
      const {user_id} = req.params;

      //query to delete interview

      db.query('DELETE FROM interview WHERE id = ? and user_id = ?',[decoded.id,user_id],(error,result) =>{
        if(error){
          console.log(error);
          return next();
        }

        if (result.affectedRows > 0) {
          res.status(200).redirect('/compdash?message=DeletedSuccessfully');
        }

      });
    } else {
      return next();
    }
  } catch (error){
    console.log(error);
    return next();
  }
};


exports.viewRegisteredStudent = async (req,res,next) =>{
  try{
    db.query('SELECT id , name , email FROM student ',async(error,result)=>{
      if(error){
        console.log(error);
        return next();
      }

      req.students = result;
      console.log("Registered users are :");
      console.log(req.students);
      return next();
    });
  } catch (error){
    console.log(error);
    return next();
  }
};

//to register interviews
/*exports.registerInterviews = async(req,res,next)=>{
  try{
    const {name,email,phone} = req.body;
    const newCandidate = {
      name,
      email,
      phone,
    }

    db.query('INSERT INTO interviewapplication SET?',newCandidate,(error,result)=>{
      if(error){
        console.log(error);
        return next();
      }
      res.status(200).render('student/registerinterview',{
        message: 'Registered Successfully'
      })

    });
  } catch(error){
    console.log(error);
    return next();
  }
}
*/


exports.registerInterviews = async (req, res, next) => {
  try {
    const { name, email, phone, user_id } = req.body; // Assume job_role is provided to identify the specific interview

    // Fetch the 'id' and 'user_id' from the 'interview' table based on 'job_role' or other criteria
    db.query('SELECT id, user_id FROM interview WHERE user_id = ?', [user_id], (error, results) => {
      if (error) {
        console.log(error);
        return next(error);
      }

      if (results.length > 0) {
        const interview = results[0];
        const newCandidate = {
          name,
          email,
          phone,
          id: interview.id,            // 'id' from 'interview' table
          interview_id: interview.user_id // 'user_id' from 'interview' table mapped to 'interview_id'
        };

        db.query('INSERT INTO interviewapplication SET ?', newCandidate, (error, result) => {
          if (error) {
            console.log(error);
            return next(error);
          }
          console.log('candidate details:',newCandidate);
          res.status(200).render('student/registerinterview', {
            message: 'Registered Successfully'
          });
        });
      } else {
        res.status(400).render('student/registerinterview', {
          message: 'No matching interview found'
        });
      }
    });
  } catch (error) {
    console.log(error);
    return next(error);
  }
};






//only admin priviledge
exports.removeStudent = async (req,res,next) =>{
  try{
    const {id} = req.params;
    //query to remove student 

    db.query('DELETE FROM student WHERE id = ?',[id],(error,result)=>{
      if(error){
        console.log(error);
        return next();
      }
      if(result.affectedRows > 0){
        res.status(200).redirect('/admindash?message=DeletedSuccessfully');
      }
    });

  } catch(error){
    console.log(error);
    return next();
  }
};


exports.addQuestions = async(req,res,next)=>{
  try{
    const {number ,question , option1 , option2 , option3 , option4 , answer} = req.body;
    const mockDetails = {
      number,
      question,
      option1,
      option2,
      option3,
      option4,
      answer
    }

    db.query('INSERT INTO mocktest SET?',mockDetails,(error,result)=>{
      if(error){
        console.log(error);
        return next();
      }
      res.status(200).render('admin/mock',{
        message: 'Question Added '
      });

    });
  } catch(error){
    console.log(error);
    return next();
  }
}


//to view the added questions and to change the values 
exports.viewQuestions = async (req, res, next) => {
  try {
      db.query('SELECT * FROM mocktest', (error, result) => {
        if (error) {
          console.log(error);
          return next();
        }

        req.mockDet = result;
        console.log("Interview details are:");
        console.log(req.mockDet);
        return next();

      });
  } catch (error) {
    console.log(error);
    return next();
  }
};

exports.viewTest = async(req,res,next)=>{
  try{
    db.query('SELECT number , question , option1 , option2 , option3 , option4  FROM mocktest',(error, result)=>{
      if(error){
        console.log(error);
        return next();
      }

      req.test = result;
      console.log(req.test);
      return next();
    });
  } catch(error){
    console.log(error);
    return next();
  }
};


//to calculate the score


exports.calculateScore = async (req, res, next) => {
  try {
    const questions = req.body.questions;

    console.log('Incoming questions data:', questions);

    if (!questions || !Array.isArray(questions)) {
      return res.status(400).json({ error: 'Invalid data format' });
    }

    // Fetch the correct answers from the database
    db.query('SELECT number, answer FROM mocktest', (error, results) => {
      if (error) {
        console.log(error);
        return res.status(500).json({ error: 'Database query error' });
      }

      // Map the results to an object for easy access
      const correctAnswers = {};
      results.forEach((result) => {
        correctAnswers[result.number] = result.answer;
      });

      console.log('Correct answers:', correctAnswers);

      // Calculate the score
      let score = 0;
      questions.forEach((question) => {
        const correctAnswer = correctAnswers[question.questionId];
        console.log('Question ID:', question.questionId);
        console.log('Selected Options:', question.selectedOptions);
        console.log('Correct Answer:', correctAnswer);

        if (correctAnswer && question.selectedOptions.includes(correctAnswer)) {
          score++;
        }
      });

      res.json({ score });
      console.log('Score:', score);
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: 'Server error' });
  }
};

exports.viewInterviewApplicants = async (req, res, next) => {
  try {
    const interviewId = req.params.interviewId; // Get the interview ID from the request parameters

    // Query to get applicants for the specific interview
    db.query(
      'SELECT ia.name, ia.email, ia.phone FROM interviewapplication ia JOIN interview i ON ia.interview_id = i.user_id WHERE i.user_id = ?',
      [interviewId],
      (error, results) => {
        if (error) {
          console.log(error);
          return next(error);
        }

        // Render a new view with the applicants' details
        res.render('company/viewlist', { applicants: results, interviewId });
      }
    );
  } catch (error) {
    console.log(error);
    return next(error);
  }
};



// to send mail if applied 


exports.acceptApplicant = async (req, res, next) => {
  const { email, name } = req.body;

  console.log('Email :',email);
  console.log('Name :',name);

  const mailOptions = {
    from: 'joelanto386@gmail.com',
    to: email,
    subject: 'Application Accepted',
    text: `Dear ${name},\n\nCongratulations! Your application has been accepted.\n\nBest regards,\nCompany Name`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return res.status(500).send({ success: false, message: 'Failed to send email.' });
    } else {
      return res.status(200).send({ success: true, message: 'Email sent successfully!' });
    }
  });
};



exports.rejectApplicant = async (req, res, next) => {
  const { email, name } = req.body;

  const mailOptions = {
    from: 'joelanto386@gmail.com',
    to: email,
    subject: 'Application Rejected',
    text: `Dear ${name},\n\nWe regret to inform you that your application has been rejected.\n\nBest regards,\nCompany Name`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return res.status(500).send({ success: false, message: 'Failed to send email.' });
    } else {
      return res.status(200).send({ success: true, message: 'Email sent successfully!' });
    }
  });
};