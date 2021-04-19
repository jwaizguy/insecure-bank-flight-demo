package org.hdivsamples.facade;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

import org.springframework.stereotype.Service;

@Service
public class StorageFacadeImpl implements StorageFacade {

	private final String url = this.getClass().getClassLoader().getResource("").getPath() + "/avatars/";

	@Override
	public boolean exists(final String fileName) {
    // JC: This line has defect
	// File file = new File(url + fileName);
	// return(true);

	return(true);

    // JC: This line does not
	//	File file = new File(fileName);
	//	return file.exists();
	}

	@Override
	public File load(final String fileName) {
		//return new File(url + fileName);
		return new File(url + "image.png");
	}

	@Override
	public void save(final InputStream inputStream, final String name) throws IOException {
		File file = new File(url + name);
		Files.copy(inputStream, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
	}
}
