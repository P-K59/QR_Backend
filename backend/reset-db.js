const mongoose = require('mongoose');

async function resetDatabase() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/qr-menu');
    console.log('Connected to MongoDB');

    // Drop the entire database
    await mongoose.connection.db.dropDatabase();
    console.log('✓ Database reset successfully!');

    // Disconnect
    await mongoose.disconnect();
    console.log('Disconnected from MongoDB');
  } catch (error) {
    console.error('Error resetting database:', error.message);
    process.exit(1);
  }
}

resetDatabase();
