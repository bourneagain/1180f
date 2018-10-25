/* CVE-2015-1538 and CVE-2015-3824
   ref. https://android.googlesource.com/platform/frameworks/av/+/edd4a76%5E!/ */

/* CVE-2015-1538: parsing mp4 file from MMS */
status_t SampleTable::setTimeToSampleParams(off64_t data_offset, size_t data_size) {
  if (mTimeToSample != NULL || data_size < 8)
    return ERROR_MALFORMED;
  
  uint8_t header[8];
  if (mDataSource->readAt(data_offset, header, sizeof(header)) < (ssize_t)sizeof(header))
    return ERROR_IO;
  ...
  mTimeToSampleCount = U32_AT(&header[4]);
  mTimeToSample = new uint32_t[mTimeToSampleCount * 2];
  size_t size = sizeof(uint32_t) * mTimeToSampleCount * 2;
  if (mDataSource->readAt(data_offset + 8, mTimeToSample, size) < (ssize_t)size)
    return ERROR_IO;
  for (uint32_t i = 0; i < mTimeToSampleCount * 2; ++i)
    mTimeToSample[i] = ntohl(mTimeToSample[i]);
  return OK;
}

/* CVE-2015-3824: parsing mp4 file from MMS */
status_t MPEG4Extractor::parseChunk(off64_t *offset, int depth) {
  uint32_t hdr[2];
  mDataSource->readAt(*offset, hdr, 8);
  uint64_t chunk_size = ntohl(hdr[0]);
  uint32_t chunk_type = ntohl(hdr[1]);
  ...
    switch(chunk_type) {
     ...
    case FOURCC('t', 'x', '3', 'g'): {
      uint32_t type;
      const void *data;
      size_t size = 0;
      if (!mLastTrack->meta->findData(kKeyTextFormatData, &type, &data, &size))
        size = 0;
      
      uint8_t *buffer = new (std::nothrow) uint8_t[size + chunk_size];
      if (buffer == NULL)
        return ERROR_MALFORMED;
      if (size > 0)
        memcpy(buffer, data, size);

      if ((size_t)(mDataSource->readAt(*offset, buffer + size, chunk_size)) < chunk_size) {
        delete[] buffer;
        buffer = NULL;
        // advance read pointer so we don't end up reading this again
        *offset += chunk_size;
        return ERROR_IO;
      }
      mLastTrack->meta->setData(kKeyTextFormatData, 0, buffer, size + chunk_size);
      delete[] buffer;
      *offset += chunk_size;
      break;
    }
    ...  
  }
}