

const mcMail = require('@mailchimp/mailchimp_transactional')('2486d29c9e57d102be870127d898a4ca-us21');



const sendMCMail = async ({ to, subject, html, attachments, text }) => {
  try {
    const response = await mcMail.users.ping({
      message: {
        subject: subject,
        from_email: 'abdussalammustapha07@gmail.com', // Replace with your verified sender email
        to: to,
        html: html,
      },
    });

    return response;
  } catch (error) {
    console.error(error);
  }
};


exports.sendEmail = async (args) => {
  if (process.env.NODE_ENV !== 'development') {
    return Promise.resolve();
  } else {
    return sendMCMail(args);
  }
};