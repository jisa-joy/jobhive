const express = require('express');
const authController = require('../controllers/auth');


const router = express.Router();


router.post('/register', authController.register);

router.post('/login', authController.login);

router.post('/adminlogin',authController.admlogin);

router.post('/adminregister',authController.admregister);

router.post('/companylogin',authController.complogin);

router.post('/companyregister',authController.compregister);

router.get('/logout',authController.logout);

router.post('/submit',authController.calculateScore);

router.post('/studentprofile',authController.updateProfile);

router.post('/changepass',authController.updatePassword);

router.post('/interviews',authController.addInterviews);

router.post('/changepassword',authController.updateCompanyPassword);

router.delete('/compdash/:user_id',authController.compisLoggedIn,authController.deleteInterview);

router.delete('/admindash/:id',authController.removeStudent);

router.post('/registerinterview',authController.registerInterviews);

router.post('/mock',authController.addQuestions);

router.post('/acceptApplicant', authController.compisLoggedIn, authController.acceptApplicant);

router.post('/rejectApplicant', authController.compisLoggedIn, authController.rejectApplicant);





module.exports = router;